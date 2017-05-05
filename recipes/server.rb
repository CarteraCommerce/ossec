#
# Cookbook Name:: cartera_ossec
# Recipe:: server
#
# Copyright (c) 2016 Cartera Commerce, Inc., All Rights Reserved.

include_recipe 'yum-epel'

iptables_rule 'iptables_ossec' do
  action :enable
end

%w(perl-Digest-MD5).each do |pkg|
  package pkg do
    action :install
  end
end

include_recipe 'ossec::install_server'

ssh_hosts = []

search_string = 'ossec:[* TO *]'
search_string << " AND policy_group:#{node['policy_group']}" unless node['policy_group'].nil?
search_string << " AND (-policy_name:#{node['ossec']['server_policy']})" unless node['ossec']['server_policy'].nil?
search_string << " AND (-fqdn:#{node['fqdn']})"

search(:node, search_string) do |n|
  ssh_hosts << n['ipaddress'] if n['keys']

# Create the agent key
  execute "#{node['ossec']['agent_manager']} -a --ip #{n['ipaddress']} -n #{n['fqdn'][0..31]}" do
    not_if "grep '#{n['fqdn'][0..31]} #{n['ipaddress']}' #{node['ossec']['dir']}/etc/client.keys"
  end
end

# begin
#   t = resources(:template => "/usr/local/bin/dist-ossec-keys.sh")
#   t.source "dist-ossec-keys-new.sh.erb"
#   t.cookbook "cartera_ossec"
#   t.variables(:ossec_dir => node['ossec']['dir'],
#     ssh_hosts: ssh_hosts.sort
#   )
#   t.not_if { ssh_hosts.empty? }
#     rescue Chef::Exceptions::ResourceNotFound
#     Chef::Log.warn "could not find template /usr/local/bin/dist-ossec-keys.sh to modify"
# end

template '/usr/local/bin/dist-ossec-keys.sh' do
  source 'dist-ossec-keys.sh.erb'
  owner 'root'
  group 'root'
  mode '755'
  variables(ssh_hosts: ssh_hosts.sort)
  not_if { ssh_hosts.empty? }
end

dbag_name = node['ossec']['data_bag']['name']
dbag_item = node['ossec']['data_bag']['ssh']
ossec_key = if node['ossec']['data_bag']['encrypted']
              Chef::EncryptedDataBagItem.load(dbag_name, dbag_item)
            else
              data_bag_item(dbag_name, dbag_item)
            end

directory "#{node['ossec']['dir']}/.ssh" do
  owner 'root'
  group 'ossec'
  mode '0750'
end

template "#{node['ossec']['dir']}/.ssh/id_rsa" do
  source 'ssh_key.erb'
  owner 'root'
  group 'ossec'
  mode '0600'
  variables(key: ossec_key['privkey'])
end

#
# Remove the use_geoip attribute, so that it doesn't get inserted into
# the ossec.conf configuration file. Ossec fails to start if it's
# in the configuration file.
#
ruby_block 'delete_unsupported_use_geoip' do
  block do
    node.rm('ossec', 'conf', 'server', 'alerts', 'use_geoip')
  end
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
  notifies :restart, 'service[ossec-server]'
  notifies :restart, 'service[ossec-csyslog]'
  notifies :restart, 'service[ossec-monitord]'
  notifies :restart, 'service[ossec-remoted]'

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
  notifies :restart, 'service[ossec-server]'
  notifies :restart, 'service[ossec-csyslog]'
  notifies :restart, 'service[ossec-monitord]'
  notifies :restart, 'service[ossec-remoted]'

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

cron 'distribute-ossec-keys' do
  minute '0'
  command '/usr/local/bin/dist-ossec-keys.sh'
  only_if { ::File.exist?("#{node['ossec']['dir']}/etc/client.keys") }
end

# Install systemd configuration
# Using systemd because we need the Restart functionality.
# OSSEC won't start without the client key. The client key
# gets installed when chef runs on the ossec server. By using
# systemd's restart, we can start the services and systemd
# will continuously try to restart until the client key is
# installed. Using systemd for the server stuff to be consistent
# with the client setup.
cookbook_file '/etc/systemd/system/ossec-server.target' do
  source 'server/ossec-server.target'
  mode 0644
  owner 'root'
  group 'root'
end

systemd_unit 'ossec-server.target' do
  action [:start, :enable]
end

cookbook_file '/etc/systemd/system/ossec-csyslog.service' do
  source 'server/ossec-csyslog.service'
  mode 0644
  owner 'root'
  group 'root'
end

service 'ossec-csyslog' do
  action [:start, :enable]
end

cookbook_file '/etc/systemd/system/ossec-monitord.service' do
  source 'server/ossec-monitord.service'
  mode 0644
  owner 'root'
  group 'root'
end

service 'ossec-monitord' do
  action [:start, :enable]
end

cookbook_file '/etc/systemd/system/ossec-remoted.service' do
  source 'server/ossec-remoted.service'
  mode 0644
  owner 'root'
  group 'root'
end

service 'ossec-remoted' do
  action [:start, :enable]
end
