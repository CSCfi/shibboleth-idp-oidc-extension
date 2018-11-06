# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
    config.vm.box = "bento-centos/7.2"
    config.vm.box_url = "http://cloud.centos.org/centos/7/vagrant/x86_64/images/CentOS-7-x86_64-Vagrant-1611_01.VirtualBox.box"
    config.ssh.insert_key = false
    config.ssh.shell = 'bash --noprofile -l'

    config.vm.provider :virtualbox do |vb|
        vb.customize ["modifyvm", :id, "--memory", "2048" ]
    end

    config.vm.define "app" do |app|
        app.vm.network "private_network", ip: "192.168.0.150"
        app.vm.hostname = "gn43-oidcshibop-devel.local"
        app.vm.provision :ansible do |ansible|
            ansible.playbook = "oidcshibop.yml"
            ansible.galaxy_role_file = "requirements.yml"
            ansible.extra_vars = {
#              service_name: "gn43-oidcshibop-devel.local",
              service_name: "192.168.0.150",
              host_name: "gn43-oidcshibop-devel",
              # Allow override copying extra jars completely by defining empty arrays
              jetty_jars: [
              ],
              # Allow overriding location of jars
              shibbolethidp_jars: [
                { name: "mariadb-java-client",
                  url: "http://central.maven.org/maven2/org/mariadb/jdbc/mariadb-java-client/1.5.9/mariadb-java-client-1.5.9.jar",
                  dst: "/opt/shibboleth-idp/edit-webapp/WEB-INF/lib/"
                },
                { name: "commons-dbcp2",
                  url: "http://central.maven.org/maven2/org/apache/commons/commons-dbcp2/2.1.1/commons-dbcp2-2.1.1.jar",
                  dst: "/opt/shibboleth-idp/edit-webapp/WEB-INF/lib/"
                },
                {
                  name: "commons-pool2",
                  url: "http://central.maven.org/maven2/org/apache/commons/commons-pool2/2.4.2/commons-pool2-2.4.2.jar",
                  dst: "/opt/shibboleth-idp/edit-webapp/WEB-INF/lib/"
                }
              ]
            }
        end
        app.vm.provision :shell, inline: "sudo /sbin/ifdown eth1 && sudo /sbin/ifup eth1"
    end
end
