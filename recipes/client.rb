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

server_recipe = node['ossec']['server_recipe']

# Search for nodes that are OSSEC Servers by looking for nodes that use the OSSEC Server policy
# node['ossec']['server_policy'] is an attribute that points to the policy used by the OSSEC servers
search_string = "run_list:\"recipe[#{server_recipe}]\"" unless node['ossec']['server_recipe'].nil?

if Chef::Config.policy_name == node['ossec']['server_policy']
  # The node running this recipe is an OSSEC Server
  ossec_server << node['ipaddress']
else
  search(:node, search_string) do |n|
    # Create a list of OSSEC Server IP Addresses
    ossec_server << n['ipaddress']
  end
end

# Set the agent_server_ip attribute to the first OSSEC Server in the list ossec_server
# This will later get inserted into the agent's configuration file
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
# We're going to use systemd instead, because systemd
# can auto-restart daemons that don't start the first time.
service "ossec-hids" do
  action [:disable, :stop]
end
file '/etc/rc.d/init.d/ossec-hids' do
  action :delete
end

ruby_block 'ossec install_type' do # ~FC014
  block do
    if node['recipes'].include?('ossec::default')
      type = 'local'
    else
      type = nil

      File.open('/etc/ossec-init.conf') do |file|
        file.each_line do |line|
          if line =~ /^TYPE="([^"]+)"/
            type = Regexp.last_match(1)
            break
          end
        end
      end
    end

    node.set['ossec']['install_type'] = type
  end
end

# Gyoku renders the XML.
chef_gem 'gyoku' do
  compile_time false if respond_to?(:compile_time)
end

file "#{node['ossec']['dir']}/etc/ossec.conf" do
  owner 'root'
  group 'ossec'
  mode '0440'
  manage_symlink_source true
  notifies :restart, 'service[ossec-agentd]'
  notifies :restart, 'service[ossec-syscheckd]'

  content lazy {
    # Merge the "typed" attributes over the "all" attributes.
    all_conf = node['ossec']['conf']['all'].to_hash
    type_conf = node['ossec']['conf'][node['ossec']['install_type']].to_hash
    conf = Chef::Mixin::DeepMerge.deep_merge(type_conf, all_conf)
    Chef::OSSEC::Helpers.ossec_to_xml('ossec_config' => conf)
  }
end

file "#{node['ossec']['dir']}/etc/shared/agent.conf" do
  owner 'root'
  group 'ossec'
  mode '0440'
  notifies :restart, 'service[ossec-agentd]'
  notifies :restart, 'service[ossec-syscheckd]'

  # Even if agent.cont is not appropriate for this kind of
  # installation, we need to create an empty file instead of deleting
  # for two reasons. Firstly, install_type is set at converge time
  # while action can't be lazy. Secondly, a subsequent package update
  # would just replace the file.
  action :create

  content lazy {
    if node['ossec']['install_type'] == 'server'
      conf = node['ossec']['agent_conf'].to_a
      Chef::OSSEC::Helpers.ossec_to_xml('agent_config' => conf)
    else
      ''
    end
  }
end

# Install systemd configuration
# Using systemd because we need the Restart functionality.
# OSSEC won't start without the client key. The client key
# gets installed when chef runs on the ossec server. By using
# systemd's restart, we can start the services and systemd
# will continuously try to restart until the client key is
# installed
cookbook_file '/etc/systemd/system/ossec-agent.target' do
  source 'agent/ossec-agent.target'
  mode 0644
  owner 'root'
  group 'root'
end

systemd_unit 'ossec-agent.target' do
  action [:start, :enable]
end

cookbook_file '/etc/systemd/system/ossec-agentd.service' do
  source 'agent/ossec-agentd.service'
  mode 0644
  owner 'root'
  group 'root'
end

service 'ossec-agentd' do
  action [:start, :enable]
end

cookbook_file '/etc/systemd/system/ossec-syscheckd.service' do
  source 'agent/ossec-syscheckd.service'
  mode 0644
  owner 'root'
  group 'root'
end

service 'ossec-syscheckd' do
  action [:start, :enable]
end
