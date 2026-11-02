control 'SV-277167' do
  title 'The macOS system must enable macOS Application Firewall.'
  desc 'The macOS Application Firewall is the built-in firewall that comes with macOS, and it must be enabled.

When the macOS Application Firewall is enabled, the flow of information within the information system and between interconnected systems will be controlled by approved authorizations.'
  desc 'check', %q(Verify the macOS system is configured to enable the Application Firewall with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
.objectForKey('EnableFirewall').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to enable the Application Firewall by installing the "com.apple.security.firewall" configuration profile.'
  impact 0.5
  tag check_id: 'C-81322r1148951_chk'
  tag severity: 'medium'
  tag gid: 'V-277167'
  tag rid: 'SV-277167r1148953_rule'
  tag stig_id: 'APPL-26-005050'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-81227r1148952_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
