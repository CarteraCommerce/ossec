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

# Search for nodes that have any ossec attibutes
search_string = 'ossec:[* TO *]'

# Search for nodes that use the same server_site as this OSSEC server
search_string << " AND server_site:#{node['server_site']}" unless node['server_site'].nil?

# Search for nodes that are in the same environment or policy_group as this OSSEC server
# NOTE - node.chef_environment isn't an attribute, chef_environment is a method in the Chef::Node object
search_string << " AND chef_environment:#{node.chef_environment}" unless node.chef_environment.nil?

# Search for nodes that aren't using the OSSEC Server Role
# node['ossec']['server_role'] is an attribute that points to Chef Role used by the OSSEC Servers
search_string << " AND (-role:#{node['ossec']['server_role']})" unless node['ossec']['server_role'].nil?

# Search for nodes that aren't using the OSSEC server policy (i.e. they aren't OSSEC servers)
# node['ossec']['server_policy'] is an attribute that points to the policy used by the OSSEC Servers
search_string << " AND (-policy_name:#{node['ossec']['server_policy']})" unless node['ossec']['server_policy'].nil?

# and that aren't this node (the node that's running this recipe from chef-client)
search_string << " AND (-fqdn:#{node['fqdn']})"

log "search_string #{search_string}"

search(:node, search_string) do |n|
  # Create a list of the agent IP Addresses
  # This list is inserted into dist-ossec-keys.sh, which distributes the agent keys
  ssh_hosts << n['ipaddress'] if n['keys']
  log "Client IP: #{n['ipaddress']}"

  # Create the agent key
  execute "#{node['ossec']['agent_manager']} -a --ip #{n['ipaddress']} -n #{n['fqdn'][0..31]}" do
    not_if "grep '#{n['fqdn'][0..31]} #{n['ipaddress']}' #{node['ossec']['dir']}/etc/client.keys"
  end
end

# Create the script that distributes the OSSEC Agent keys
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
# the ossec.conf configuration file. OSSEC fails to start if it's
# in the configuration file.
#
ruby_block 'delete_unsupported_use_geoip' do
  block do
    node.rm('ossec', 'conf', 'server', 'alerts', 'use_geoip')
  end
end

# Disable the System V init that's installed by the RPM
# We're going to use systemd instead
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

# Cron jobs to run chef-client, which will create keys for new clients
# and distribute the keys to the clients.
cron 'chef-client' do
  minute '50'
  command '/usr/bin/chef-client > /var/log/chef-client.log 2>&1'
end

cron 'distribute-ossec-keys' do
  minute '0'
  command '/usr/local/bin/dist-ossec-keys.sh > /var/ossec/log/dist-ossec-keys.log 2>&1'
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
cookbook_file '/etc/systemd/system/ossec-csyslog.service' do
  source 'server/ossec-csyslog.service'
  mode 0644
  owner 'root'
  group 'root'
end

service 'ossec-csyslog' do
  action [:enable]
end

cookbook_file '/etc/systemd/system/ossec-analysisd.service' do
  source 'server/ossec-analysisd.service'
  mode 0644
  owner 'root'
  group 'root'
end

service 'ossec-analysisd' do
  action [:enable]
end

cookbook_file '/etc/systemd/system/ossec-monitord.service' do
  source 'server/ossec-monitord.service'
  mode 0644
  owner 'root'
  group 'root'
end

service 'ossec-monitord' do
  action [:enable]
end

cookbook_file '/etc/systemd/system/ossec-remoted.service' do
  source 'server/ossec-remoted.service'
  mode 0644
  owner 'root'
  group 'root'
end

service 'ossec-remoted' do
  action [:enable]
end

cookbook_file '/etc/systemd/system/ossec-server.target' do
  source 'server/ossec-server.target'
  mode 0644
  owner 'root'
  group 'root'
end

systemd_unit 'ossec-server.target' do
  action [:start, :enable]
end
