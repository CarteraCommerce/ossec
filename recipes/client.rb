#
# Cookbook:: ossec
# Recipe:: client
#
# Copyright:: 2010-2017, Chef Software, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

ossec_server = []

include_recipe 'yum-epel'

iptables_rule 'iptables_ossec' do
  action :enable
end

%w(perl-Digest-MD5 expect).each do |pkg|
  package pkg do
    action :install
  end
end

search_string = "policy_name:#{node['ossec']['server_policy']}" unless node['ossec']['server_policy'].nil?

# search_string << " AND chef_environment:#{node['ossec']['server_env']}" unless node['ossec']['server_env'].nil?

if Chef::Config.policy_name == node['ossec']['server_policy']
  ossec_server << node['ipaddress']
else
  search(:node, search_string) do |n|
    ossec_server << n['ipaddress']
  end
end

node.set['ossec']['agent_server_ip'] = ossec_server.first

include_recipe 'ossec::install_agent'

dbag_name = node['ossec']['data_bag']['name']
dbag_item = node['ossec']['data_bag']['ssh']
ossec_key = if node['ossec']['data_bag']['encrypted']
              Chef::EncryptedDataBagItem.load(dbag_name, dbag_item)
            else
              data_bag_item(dbag_name, dbag_item)
            end

# The install.sh script creates the ossec users and sets their shell to /sbin/nologin,
# which prevents remote commands from running. The following changes the shell to /bin/bash,
# so that scp can run.
user 'ossec' do
  action :modify
  shell '/bin/bash'
end

directory "#{node['ossec']['dir']}/.ssh" do
  owner 'ossec'
  group 'ossec'
  mode '0750'
end

template "#{node['ossec']['dir']}/.ssh/authorized_keys" do
  source 'ssh_key.erb'
  owner 'ossec'
  group 'ossec'
  mode '0600'
  variables(key: ossec_key['pubkey'])
end

# Change the selinux label on the authorized_keys file to allow
# public key authentication where the authorized_keys file isn't
# in a standard location
selinux_policy_fcontext "#{node['ossec']['dir']}/.ssh/authorized_keys" do
  secontext 'ssh_home_t'
  action :addormodify
end

file "#{node['ossec']['dir']}/etc/client.keys" do
  owner 'ossec'
  group 'ossec'
  mode '0660'
end

# Disable the System V init that's installed by the RPM
# We're going to use systemd instead
service "ossec-hids" do
  action [:disable, :stop]
end
file '/etc/rc.d/init.d/ossec-hids' do
  action :delete
end

# Install systemd configuration
# Using systemd because we need the Restart functionality.
# OSSEC won't start without the client key. The client key
# gets installed when chef runs on the ossec server.
cookbook_file '/etc/systemd/system/ossec-agent.target' do
  source 'agent/ossec-agent.target'
  mode 0644
  owner 'root'
  group 'root'
end

systemd_unit 'ossec-agent.target' do
  action [:enable]
end

cookbook_file '/etc/systemd/system/ossec-agentd.service' do
  source 'agent/ossec-agentd.service'
  mode 0644
  owner 'root'
  group 'root'
end

systemd_unit 'ossec-agentd.service' do
  action [:enable]
end

cookbook_file '/etc/systemd/system/ossec-syscheckd.service' do
  source 'agent/ossec-syscheckd.service'
  mode 0644
  owner 'root'
  group 'root'
end

systemd_unit 'ossec-syscheckd.service' do
  action [:enable]
end

include_recipe 'ossec::common'
