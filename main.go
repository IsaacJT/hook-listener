package main;

import (
  "net/http"
  "crypto/sha1"
  "io/ioutil"
  "log"
  "crypto/hmac"
  "gopkg.in/yaml.v2"
  "encoding/hex"
  "errors"
  "encoding/json"
  "path"
  "os"
  "strings"
  "os/exec"
)

type Config struct {
  Secret string `yaml:"secret"`
  GitDir string `yaml:"git_dir"`
}

type HookRepository struct {
  Name string `json:"name"`
}

type HookDelivery struct {
  Repository HookRepository `json:"repository"`
}

var (
  config Config
)

// exists returns whether the given file or directory exists or not
func exists(path string) (bool, error) {
    _, err := os.Stat(path)
    if err == nil { return true, nil }
    if os.IsNotExist(err) { return false, nil }
    return true, err
}

func pullRepo(delivery *HookDelivery) error {
  repoPath := path.Clean(path.Join(config.GitDir, delivery.Repository.Name))
  if realDir, _ := exists(repoPath); !strings.HasPrefix(repoPath, config.GitDir) || !realDir {
    return errors.New("Destination path is invalid")
  }
  if err := os.Chdir(repoPath); err != nil {
    return err
  }
  if cmd := exec.Command("git", "pull", "-f"); cmd == nil {
    return errors.New("Error executing git pull for '" +  delivery.Repository.Name + "'")
  }
  log.Println("Successfully pulled '", delivery.Repository.Name, "'")
  return nil
}

// checkMAC reports whether messageMAC is a valid HMAC tag for message.
func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func handler(w http.ResponseWriter, r *http.Request) {
  if (r.Method != "POST") {
    w.WriteHeader(http.StatusMethodNotAllowed)
    return
  }
  defer r.Body.Close()
  body, _ := ioutil.ReadAll(r.Body)
  signature := r.Header.Get("X-Hub-Signature")
  hmac := make([]byte, 20)
  if (len(signature) > 5) {
    hex.Decode(hmac, []byte(signature[5:]))
  } else {
    w.WriteHeader(http.StatusBadRequest)
    return
  }
  if (checkMAC([]byte(body),
                hmac,
                []byte(config.Secret))) {
    delivery := HookDelivery{}

    if err := json.Unmarshal(body, &delivery); err != nil  {
      w.WriteHeader(http.StatusInternalServerError)
      w.Write([]byte(err.Error()))
      return
    }
    log.Println("Secret accepted for " + delivery.Repository.Name)
    if err := pullRepo(&delivery); err != nil {
      w.WriteHeader(http.StatusInternalServerError)
      w.Write([]byte(err.Error()))
      return
    } else {
      w.WriteHeader(http.StatusOK)
    }

  } else {
    log.Println("Invalid secret")
    w.WriteHeader(http.StatusUnauthorized)
    return
  }
}

func loadConfig() Config {
  contents, err := ioutil.ReadFile("config.yaml")
  newConfig := Config{}
  if err == nil {
    err = yaml.Unmarshal(contents, &newConfig)
    if err != nil {
      log.Fatal(err)
    } else {
      log.Println("Loaded config")
    }
  } else {
    log.Println("Warning: empty config.yaml")
  }
  return newConfig
}

func main() {
  config = loadConfig()
  http.HandleFunc("/", handler)
  http.ListenAndServe("127.0.0.1:13000", nil)
}
