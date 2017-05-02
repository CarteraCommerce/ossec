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

include_recipe 'install_server'

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

include_recipe 'common'

cron 'distribute-ossec-keys' do
  minute '0'
  command '/usr/local/bin/dist-ossec-keys.sh'
  only_if { ::File.exist?("#{node['ossec']['dir']}/etc/client.keys") }
end
