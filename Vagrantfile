# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
    config.vm.box = "bento-centos/7.2"
    config.vm.box_url = "http://cloud.centos.org/centos/7/vagrant/x86_64/images/CentOS-7-x86_64-Vagrant-1611_01.VirtualBox.box"
    config.ssh.insert_key = false
    config.ssh.shell = 'bash --noprofile -l'

    config.vm.define "app" do |app|
        app.vm.network "private_network", ip: "192.168.0.150"
        app.vm.hostname = "gn43-oidcshibop-devel.local"
        app.vm.provision :ansible do |ansible|
            ansible.playbook = "oidcshibop.yml"
            ansible.galaxy_role_file = "requirements.yml"
            ansible.extra_vars = {
              service_name: "gn43-oidcshibop-devel.local",
              host_name: "gn43-oidcshibop-devel"
            }
        end
        app.vm.provision :shell, inline: "sudo /sbin/ifdown eth1 && sudo /sbin/ifup eth1"
    end
end
