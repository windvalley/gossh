/*
Copyright © 2021 windvalley

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package inventory

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/go-project-pkg/expandhost"
)

type hostVarType int

// Host target host.
type Host struct {
	Alias      string
	Host       string
	Port       int
	User       string
	Password   string
	Keys       []string
	Passphrase string
}

const (
	hostVarHost hostVarType = iota
	hostVarPort
	hostVarUser
	hostVarPassword
	hostVarKeys
	hostVarPassphrase
)

// idenditfiers
const (
	comment = "#"

	groupSurroundLeft  = "["
	groupSurroundRight = "]"
	groupSplit         = ":"
	groupVar           = "vars"
	groupChildren      = "children"

	hostVarSplit = "="

	noGroupIdentifier = "nogroup"
)

var hostVarsMap = map[hostVarType]string{
	hostVarHost:       "host",
	hostVarPort:       "port",
	hostVarUser:       "user",
	hostVarPassword:   "password",
	hostVarKeys:       "keys",
	hostVarPassphrase: "passphrase",
}

var (
	groupOrder []string

	groupMap         = make(map[string][]string)
	groupVarMap      = make(map[string][]string)
	groupChildrenMap = make(map[string][]string)

	groupHostsMap = make(map[string][]*Host)
	aliasHostsMap = make(map[string]*Host)
)

var hostVars []string

func init() {
	for _, v := range hostVarsMap {
		hostVars = append(hostVars, v)
	}
}

// Parse inventory file.
func Parse(inventoryFile string) error {
	if err := buildRawGroups(inventoryFile); err != nil {
		return err
	}

	if err := buildGroupHostsMap(); err != nil {
		return err
	}

	buildAliasHostsMap()

	return nil
}

// GetAllHosts that from inventory file.
func GetAllHosts() []*Host {
	var hosts []*Host

	for _, v := range groupOrder {
		hosts = append(hosts, groupHostsMap[v]...)
	}

	return DeDuplHosts(hosts)
}

// GetHostsByGroup get hosts by host group name.
func GetHostsByGroup(groupName string) []*Host {
	return groupHostsMap[groupName]
}

// GetHostByAlias get host by its alias name(the first field).
func GetHostByAlias(hostAlias string) *Host {
	return aliasHostsMap[hostAlias]
}

// DeDuplHosts deduplicate the hosts.
func DeDuplHosts(hosts []*Host) []*Host {
	var set []*Host

	keys := make(map[string]bool)

	for _, v := range hosts {
		if !keys[v.Alias] {
			set = append(set, v)
			keys[v.Alias] = true
		}
	}

	return set
}

func buildGroupHostsMap() error {
	for group, rawHosts := range groupMap {
		var hosts []*Host

		for _, hostline := range rawHosts {
			_hosts, err := buildHosts(hostline, group)
			if err != nil {
				return err
			}

			hosts = append(hosts, _hosts...)
		}

		groupHostsMap[group] = append(groupHostsMap[group], hosts...)
	}

	for group, children := range groupChildrenMap {
		var hosts []*Host
		for _, subGroup := range children {
			hosts = append(hosts, groupHostsMap[subGroup]...)
		}

		groupHostsMap[group] = hosts
	}

	return nil
}

func buildAliasHostsMap() {
	for _, hosts := range groupHostsMap {
		for _, v := range hosts {
			aliasHostsMap[v.Alias] = v
		}
	}
}

func buildRawGroups(inventoryFile string) error {
	lines, err := parse(inventoryFile)
	if err != nil {
		return err
	}

	noGroupFlag := 0
	varGroupFlag := 0
	childrenGroupFlag := 0

	var (
		groupVarName      string
		groupChildrenName string
		groupName         string
	)

	isFirstLine := true
	for _, v := range lines {
		v = strings.TrimSpace(v)
		if err := checkLine(v); err != nil {
			return err
		}

		switch {
		case strings.HasSuffix(v, groupSplit+groupVar+groupSurroundRight):
			if isFirstLine {
				isFirstLine = false
			}
			_varGroupName := strings.Split(v, groupSplit)[0]
			groupVarName = strings.TrimPrefix(_varGroupName, groupSurroundLeft)
			varGroupFlag = 1
			noGroupFlag = 0
			childrenGroupFlag = 0
			continue
		case strings.HasSuffix(v, groupSplit+groupChildren+groupSurroundRight):
			if isFirstLine {
				isFirstLine = false
			}
			_groupChildrenName := strings.Split(v, groupSplit)[0]
			groupChildrenName = strings.TrimPrefix(_groupChildrenName, groupSurroundLeft)
			childrenGroupFlag = 1
			noGroupFlag = 0
			varGroupFlag = 0
			continue
		case strings.HasPrefix(v, groupSurroundLeft):
			if isFirstLine {
				isFirstLine = false
			}
			groupName = strings.TrimPrefix(v, groupSurroundLeft)
			groupName = strings.TrimSuffix(groupName, groupSurroundRight)

			groupOrder = append(groupOrder, groupName)

			noGroupFlag = 0
			varGroupFlag = 0
			childrenGroupFlag = 0
			continue
		default:
			if isFirstLine {
				groupOrder = append(groupOrder, noGroupIdentifier)
				noGroupFlag = 1
				isFirstLine = false
			}
			if noGroupFlag == 1 {
				groupMap[noGroupIdentifier] = append(groupMap[noGroupIdentifier], v)
			} else if varGroupFlag == 1 {
				groupVarMap[groupVarName] = append(groupVarMap[groupVarName], v)
			} else if childrenGroupFlag == 1 {
				groupChildrenMap[groupChildrenName] = append(groupChildrenMap[groupChildrenName], v)
			} else {
				groupMap[groupName] = append(groupMap[groupName], v)
			}
		}
	}

	return nil
}

func checkLine(line string) error {
	if strings.HasPrefix(line, groupSurroundLeft) {
		if !strings.HasSuffix(line, groupSurroundRight) {
			return fmt.Errorf("invalid group name definition: %s", line)
		}

		parts := strings.Split(line, groupSplit)
		partsLen := len(parts)
		if partsLen != 2 && partsLen != 1 {
			return fmt.Errorf("invalid group name definition: %s", line)
		}

		if partsLen == 2 {
			prop := strings.TrimSuffix(parts[1], groupSurroundRight)
			if prop != groupVar && prop != groupChildren {
				return fmt.Errorf(
					"invalid group properties '%s', available properties: %s, %s",
					prop,
					groupVar,
					groupChildren,
				)
			}
		}
	}

	return nil
}

func parse(file string) ([]string, error) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")

	var newLines []string
	for _, l := range lines {
		if l == "" || strings.HasPrefix(l, comment) {
			continue
		}

		newLines = append(newLines, l)
	}

	return newLines, nil
}

//nolint:funlen,gocyclo
func buildHosts(hostLine string, group string) ([]*Host, error) {
	hostFields := strings.Fields(hostLine)

	hostAlias := hostFields[0]

	var (
		host       string
		port       int
		user       string
		password   string
		keys       []string
		passphrase string

		err error
	)

	varsMap := make(map[string]string)
	vars := groupVarMap[group]
	for _, v := range vars {
		kv := strings.Split(v, hostVarSplit)
		if len(kv) != 2 {
			return nil, fmt.Errorf(
				"invalid host var format '%s' in group vars '[%s:vars]', format must be: varName%svarValue",
				v,
				group,
				hostVarSplit,
			)
		}

		varName := kv[0]
		if !hasEntry(hostVars, varName) {
			return nil, fmt.Errorf(
				"indvalid host var '%s' in group vars '[%s:vars]', available vars: %s",
				varName,
				group,
				hostVars,
			)
		}

		varsMap[kv[0]] = kv[1]
	}

	if _host, ok := varsMap[hostVarsMap[hostVarHost]]; ok {
		host = _host
	}
	if _port, ok := varsMap[hostVarsMap[hostVarPort]]; ok {
		portInt, err1 := strconv.Atoi(_port)
		if err1 != nil {
			return nil, fmt.Errorf("invalid port: %s", _port)
		}

		port = portInt
	}
	if _user, ok := varsMap[hostVarsMap[hostVarUser]]; ok {
		user = _user
	}
	if _password, ok := varsMap[hostVarsMap[hostVarPassword]]; ok {
		password = _password
	}
	if _keys, ok := varsMap[hostVarsMap[hostVarKeys]]; ok {
		keys = strings.Split(_keys, ",")
	}
	if _passphrase, ok := varsMap[hostVarsMap[hostVarPassphrase]]; ok {
		passphrase = _passphrase
	}

	if len(hostFields) > 1 {
		for _, v := range hostFields[1:] {
			items := strings.Split(v, hostVarSplit)

			if len(items) != 2 {
				return nil, fmt.Errorf(
					"indvalid host var format '%s' in host entry '%s', format must be: varName%svarValue",
					v,
					hostLine,
					hostVarSplit,
				)
			}

			hostVar := items[0]
			varValue := items[1]

			switch hostVar {
			case hostVarsMap[hostVarHost]:
				host = varValue
			case hostVarsMap[hostVarPort]:
				port, err = strconv.Atoi(varValue)
				if err != nil {
					return nil, err
				}
			case hostVarsMap[hostVarUser]:
				user = varValue
			case hostVarsMap[hostVarPassword]:
				password = varValue
			case hostVarsMap[hostVarKeys]:
				keys = strings.Split(varValue, ",")
			case hostVarsMap[hostVarPassphrase]:
				passphrase = varValue
			default:
				return nil, fmt.Errorf(
					"indvalid host var '%s' in host entry '%s', available vars: %s",
					hostVar,
					hostLine,
					hostVars,
				)
			}
		}
	}

	aliasList, err := expandhost.PatternToHosts(hostAlias)
	if err != nil {
		return nil, err
	}

	var hosts []*Host
	for _, v := range aliasList {
		var _host string
		if host == "" {
			_host = v
		} else {
			_host = host
		}

		hosts = append(hosts, &Host{
			Alias:      v,
			Host:       _host,
			Port:       port,
			User:       user,
			Password:   password,
			Keys:       keys,
			Passphrase: passphrase,
		})
	}

	return hosts, nil
}

func hasEntry(items []string, item string) bool {
	for _, v := range items {
		if v == item {
			return true
		}
	}
	return false
}
