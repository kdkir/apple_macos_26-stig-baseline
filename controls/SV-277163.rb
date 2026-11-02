control 'SV-277163' do
  title 'The macOS system must configure install.log retention to 365.'
  desc 'The install.log must be configured to require that records be kept for an organizational-defined value before deletion, unless the system uses a central audit record storage facility.

Proper audit storage capacity is crucial to ensuring the ongoing logging of critical events.'
  desc 'check', %q(Verify the macOS system is configured with install.log retention to 365 with the following command:

/usr/sbin/aslmanager -dd 2>&1 | /usr/bin/awk '/\/var\/log\/install.log$/ {count++} /Processing module com.apple.install/,/Finished/ { for (i=1;i<=NR;i++) { if ($i == "TTL" && $(i+2) >= 365) { ttl="True" }; if ($i == "MAX") {max="True"}}} END{if (count > 1) { print "Multiple config files for /var/log/install, manually remove the extra files"} else if (max == "True") { print "all_max setting is configured, must be removed" } if (ttl != "True") { print "TTL not configured" } else { print "Yes" }}' 

If the result is not "yes", this is a finding.)
  desc 'fix', %q(Configure the macOS system with install.log retention to 365 with the following command:

/usr/bin/sed -i '' "s/\* file \/var\/log\/install.log.*/\* file \/var\/log\/install.log format='\$\(\(Time\\)\(JZ\\)\\) \$Host \$\(Sender\\)\[\$\(PID\\\)\]: \$Message' rotate=utc compress file_max=50M size_only ttl=365/g" /etc/asl/com.apple.install

Note: If multiple configuration files in /etc/asl are set to process the file /var/log/install.log, these files must be manually removed.)
  impact 0.3
  tag check_id: 'C-81318r1148939_chk'
  tag severity: 'low'
  tag gid: 'V-277163'
  tag rid: 'SV-277163r1148941_rule'
  tag stig_id: 'APPL-26-004050'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-81223r1148940_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
