control 'SV-277088' do
  title 'The macOS system must disable Bonjour multicast.'
  desc 'Bonjour multicast advertising must be disabled to prevent the system from broadcasting its presence and available services over network interfaces.'
  desc 'check', %q(Verify the macOS system is configured to disable Bonjour multicast with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.mDNSResponder')\
.objectForKey('NoMulticastAdvertisements').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Bonjour multicast by installing the "com.apple.mDNSResponder" configuration profile.'
  impact 0.5
  tag check_id: 'C-81243r1148714_chk'
  tag severity: 'medium'
  tag gid: 'V-277088'
  tag rid: 'SV-277088r1148716_rule'
  tag stig_id: 'APPL-26-002005'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81148r1148715_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
