package configjs_plugin

import (
        "github.com/LeakIX/l9format"
        "regexp"
        "strings"
)

type ConfigJsHttpPlugin struct {
        l9format.ServicePluginBase
}

func (ConfigJsHttpPlugin) GetVersion() (int, int, int) {
        return 0, 0, 1
}

func (ConfigJsHttpPlugin) GetRequests() []l9format.WebPluginRequest {
        return []l9format.WebPluginRequest{{
                Method:  "GET",
                Path:    "/js../.git/config",
                Headers: map[string]string{},
                Body:    []byte(""),
        }}
}

func (ConfigJsHttpPlugin) GetName() string {
        return "ConfigJsHttpPlugin"
}

func (ConfigJsHttpPlugin) GetStage() string {
        return "open"
}

func (plugin ConfigJsHttpPlugin) Verify(request l9format.WebPluginRequest, response l9format.WebPluginResponse, event *l9format.L9Event, options map[string]string) (hasLeak bool) {
        if !request.EqualAny(plugin.GetRequests()) || response.Response.StatusCode != 200 {
                return false
        }
        lowerBody := strings.ToLower(string(response.Body))
        if len(lowerBody) < 10 {
                return false
        }

        // Vérification de la présence de la chaîne "repositoryformatversion"
        if strings.Contains(lowerBody, "repositoryformatversion") {
                event.Service.Software.Name = "GitConfigFile"
                event.Leak.Type = "config_leak"
                event.Leak.Severity = "high"
                event.AddTag("potential-git-config-leak")
                event.Summary = "Found repositoryformatversion in /js../.git/config:\n" + string(response.Body)
                return true
        }

        return false
}
