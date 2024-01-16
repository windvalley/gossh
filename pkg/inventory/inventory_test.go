package inventory

import (
	"fmt"
	"os"
	"reflect"
	"testing"
)

func TestGetAllHosts(t *testing.T) {
	inventoryFile := "hosts_example.txt"

	if err := Parse(inventoryFile); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	tests := []struct {
		name string
		want []*Host
	}{
		{
			name: "case1",
			want: []*Host{
				{
					Alias:      "alias_name_node1",
					Host:       "node1.sre.im",
					Port:       0,
					User:       "",
					Password:   "",
					Keys:       nil,
					Passphrase: "",
				},
				{
					Alias:      "node100.sre.im",
					Host:       "node100.sre.im",
					Port:       0,
					User:       "",
					Password:   "",
					Keys:       nil,
					Passphrase: "",
				},
				{
					Alias:    "alias_name_node2",
					Host:     "192.168.33.12",
					Port:     8022,
					User:     "vagrant",
					Password: "123456",
					Keys: []string{
						"~/.ssh/id_rsa",
						"~/.ssh/id_ecdsa",
					},
					Passphrase: "xxx",
				},
				{
					Alias:      "node06.sre.im",
					Host:       "node06.sre.im",
					Port:       9022,
					User:       "lisi",
					Password:   "654321",
					Keys:       nil,
					Passphrase: "",
				},
				{
					Alias:      "node07.sre.im",
					Host:       "node07.sre.im",
					Port:       9022,
					User:       "lisi",
					Password:   "654321",
					Keys:       nil,
					Passphrase: "",
				},
				{
					Alias:      "node08.sre.im",
					Host:       "node08.sre.im",
					Port:       8033,
					User:       "wangwu",
					Password:   "",
					Keys:       nil,
					Passphrase: "",
				},
				{
					Alias:      "192.168.1.10",
					Host:       "192.168.1.10",
					Port:       0,
					User:       "vagrant2",
					Password:   "abcdefg",
					Keys:       nil,
					Passphrase: "",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetAllHosts(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAllHosts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetHostsByGroup(t *testing.T) {
	type args struct {
		groupName string
	}
	tests := []struct {
		name string
		args args
		want []*Host
	}{
		{
			name: "case1",
			args: args{groupName: "webserver"},
			want: []*Host{
				{
					Alias:    "alias_name_node2",
					Host:     "192.168.33.12",
					Port:     8022,
					User:     "vagrant",
					Password: "123456",
					Keys: []string{
						"~/.ssh/id_rsa",
						"~/.ssh/id_ecdsa",
					},
					Passphrase: "xxx",
				},
				{
					Alias:      "node06.sre.im",
					Host:       "node06.sre.im",
					Port:       9022,
					User:       "lisi",
					Password:   "654321",
					Keys:       nil,
					Passphrase: "",
				},
				{
					Alias:      "node07.sre.im",
					Host:       "node07.sre.im",
					Port:       9022,
					User:       "lisi",
					Password:   "654321",
					Keys:       nil,
					Passphrase: "",
				},
				{
					Alias:      "node08.sre.im",
					Host:       "node08.sre.im",
					Port:       8033,
					User:       "wangwu",
					Password:   "",
					Keys:       nil,
					Passphrase: "",
				},
			},
		},
		{
			name: "case2",
			args: args{groupName: "xxxgroup"},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetHostsByGroup(tt.args.groupName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetHostsByGroup() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetHostByAlias(t *testing.T) {
	type args struct {
		hostAlias string
	}
	tests := []struct {
		name string
		args args
		want *Host
	}{
		{
			name: "case1",
			args: args{hostAlias: "node06.sre.im"},
			want: &Host{
				Alias:      "node06.sre.im",
				Host:       "node06.sre.im",
				Port:       9022,
				User:       "lisi",
				Password:   "654321",
				Keys:       nil,
				Passphrase: "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetHostByAlias(tt.args.hostAlias); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetHostByAlias() = %v, want %v", got, tt.want)
			}
		})
	}
}
