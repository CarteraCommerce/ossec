#
# Cookbook:: ossec
# Recipe:: common
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
