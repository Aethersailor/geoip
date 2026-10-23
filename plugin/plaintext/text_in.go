package plaintext

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Loyalsoldier/geoip/lib"
)

const (
	TypeTextIn = "text"
	DescTextIn = "Convert plaintext IP & CIDR to other formats"
)

func init() {
	lib.RegisterInputConfigCreator(TypeTextIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return NewTextInFromBytes(action, data)
	})
	lib.RegisterInputConverter(TypeTextIn, &text_in{
		Description: DescTextIn,
	})
}

func NewTextIn(action lib.Action, opts ...lib.InputOption) (lib.InputConverter, error) {
	return newTextIn(TypeTextIn, DescTextIn, action, opts...)
}

func NewTextInFromBytes(action lib.Action, data []byte) (lib.InputConverter, error) {
	return newTextInFromBytes(TypeTextIn, DescTextIn, action, data)
}

func (t *text_in) GetType() string {
	return t.Type
}

func (t *text_in) GetAction() lib.Action {
	return t.Action
}

func (t *text_in) GetDescription() string {
	return t.Description
}

func (t *text_in) Input(container lib.Container) (lib.Container, error) {
	entries := make(map[string]*lib.Entry)
	var err error

	switch {
	case t.InputDir != "":
		err = t.walkDir(t.InputDir, entries)

	case t.Name != "" && (t.URI != "" || len(t.URIList) > 0):
		err = t.walkFileCandidates(t.Name, entries)
		if err != nil {
			if !t.Optional {
				return nil, fmt.Errorf("❌ [type %s | action %s] %w", t.Type, t.Action, err)
			}
			log.Printf("⚠️ [type %s | action %s] skip optional source for list %s: %s", t.Type, t.Action, strings.ToUpper(strings.TrimSpace(t.Name)), err)
			err = nil
		}

		if len(t.IPOrCIDR) > 0 {
			err = t.appendIPOrCIDR(t.IPOrCIDR, t.Name, entries)
		}

	case t.Name != "" && len(t.IPOrCIDR) > 0:
		err = t.appendIPOrCIDR(t.IPOrCIDR, t.Name, entries)

	default:
		return nil, fmt.Errorf("❌ [type %s | action %s] config missing argument inputDir or name or uri or uriList or ipOrCIDR", t.Type, t.Action)
	}

	if err != nil {
		return nil, fmt.Errorf("❌ [type %s | action %s] %w", t.Type, t.Action, err)
	}

	ignoreIPType := lib.GetIgnoreIPType(t.OnlyIPType)

	if len(entries) == 0 {
		if t.Optional {
			log.Printf("⚠️ [type %s | action %s] no entry is generated, skip optional input %s", t.Type, t.Action, strings.ToUpper(strings.TrimSpace(t.Name)))
			return container, nil
		}
		return nil, fmt.Errorf("❌ [type %s | action %s] no entry is generated", t.Type, t.Action)
	}

	for _, entry := range entries {
		switch t.Action {
		case lib.ActionAdd:
			if err := container.Add(entry, ignoreIPType); err != nil {
				return nil, fmt.Errorf("❌ [type %s | action %s] %w", t.Type, t.Action, err)
			}
		case lib.ActionRemove:
			if err := container.Remove(entry, lib.CaseRemovePrefix, ignoreIPType); err != nil {
				return nil, fmt.Errorf("❌ [type %s | action %s] %w", t.Type, t.Action, err)
			}
		default:
			return nil, fmt.Errorf("❌ [type %s | action %s] %w", t.Type, t.Action, lib.ErrUnknownAction)
		}
	}

	return container, nil
}

func (t *text_in) walkDir(dir string, entries map[string]*lib.Entry) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		if err := t.walkLocalFile(path, "", entries); err != nil {
			return err
		}

		return nil
	})

	return err
}

func (t *text_in) getSourceList() []string {
	list := make([]string, 0, 1+len(t.URIList))
	seen := make(map[string]bool, 1+len(t.URIList))

	add := func(source string) {
		source = strings.TrimSpace(source)
		if source == "" || seen[source] {
			return
		}

		seen[source] = true
		list = append(list, source)
	}

	add(t.URI)
	for _, source := range t.URIList {
		add(source)
	}

	return list
}

func (t *text_in) walkFile(pathOrURL, name string, entries map[string]*lib.Entry) error {
	switch {
	case strings.HasPrefix(strings.ToLower(pathOrURL), "http://"), strings.HasPrefix(strings.ToLower(pathOrURL), "https://"):
		return t.walkRemoteFile(pathOrURL, name, entries)
	default:
		return t.walkLocalFile(pathOrURL, name, entries)
	}
}

func (t *text_in) walkFileCandidates(name string, entries map[string]*lib.Entry) error {
	sources := t.getSourceList()
	if len(sources) == 0 {
		return fmt.Errorf("❌ [type %s | action %s] missing uri or uriList", t.Type, t.Action)
	}

	lastErr := error(nil)
	for _, source := range sources {
		err := t.walkFile(source, name, entries)
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("❌ [type %s | action %s] failed to load all sources for %s: %w", t.Type, t.Action, strings.ToUpper(strings.TrimSpace(name)), lastErr)
}

func (t *text_in) walkLocalFile(path, name string, entries map[string]*lib.Entry) error {
	entryName := ""
	name = strings.TrimSpace(name)
	if name != "" {
		entryName = name
	} else {
		entryName = filepath.Base(path)

		// check filename
		if !regexp.MustCompile(`^[a-zA-Z0-9_.\-]+$`).MatchString(entryName) {
			return fmt.Errorf("filename %s cannot be entry name, please remove special characters in it", entryName)
		}

		// remove file extension but not hidden files of which filename starts with "."
		dotIndex := strings.LastIndex(entryName, ".")
		if dotIndex > 0 {
			entryName = entryName[:dotIndex]
		}
	}

	entryName = strings.ToUpper(entryName)

	if len(t.Want) > 0 && !t.Want[entryName] {
		return nil
	}
	if _, found := entries[entryName]; found {
		return fmt.Errorf("found duplicated list %s", entryName)
	}

	entry := lib.NewEntry(entryName)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := t.scanFile(file, entry); err != nil {
		return err
	}

	entries[entryName] = entry

	return nil
}

func (t *text_in) walkRemoteFile(url, name string, entries map[string]*lib.Entry) error {
	name = strings.ToUpper(name)
	if len(t.Want) > 0 && !t.Want[name] {
		return nil
	}

	reader, err := lib.GetRemoteURLReader(url)
	if err != nil {
		return fmt.Errorf("❌ [type %s | action %s] failed to get remote file %s: %w", t.Type, t.Action, url, err)
	}
	defer reader.Close()

	entry := lib.NewEntry(name)
	if err := t.scanFile(reader, entry); err != nil {
		return err
	}

	entries[name] = entry

	return nil
}

func (t *text_in) appendIPOrCIDR(ipOrCIDR []string, name string, entries map[string]*lib.Entry) error {
	if len(ipOrCIDR) == 0 {
		return nil
	}

	name = strings.ToUpper(name)

	entry, found := entries[name]
	if !found {
		entry = lib.NewEntry(name)
	}

	for _, cidr := range ipOrCIDR {
		if err := entry.AddPrefix(strings.TrimSpace(cidr)); err != nil {
			return err
		}
	}

	entries[name] = entry

	return nil
}
