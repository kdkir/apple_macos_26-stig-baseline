control 'SV-277090' do
  title 'The macOS system must disable Internet Sharing.'
  desc 'If the system does not require Internet Sharing, support for it is nonessential and must be disabled.

The information system must be configured to provide only essential capabilities. Disabling Internet Sharing helps prevent unauthorized connection of devices, transfer of information, and tunneling.'
  desc 'check', %q(Verify the macOS system is configured to disable Internet Sharing with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('forceInternetSharingOff').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Internet Sharing by installing the "com.apple.MCX" configuration profile.'
  impact 0.5
  tag check_id: 'C-81245r1148720_chk'
  tag severity: 'medium'
  tag gid: 'V-277090'
  tag rid: 'SV-277090r1148722_rule'
  tag stig_id: 'APPL-26-002007'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81150r1148721_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
