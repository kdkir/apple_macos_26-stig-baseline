control 'SV-277100' do
  title 'The macOS system must disable Siri.'
  desc 'Support for Siri is nonessential and must be disabled.

The information system must be configured to provide only essential capabilities. Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', %q(Verify the macOS system is configured to disable Siri with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAssistant').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Siri by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81255r1148750_chk'
  tag severity: 'medium'
  tag gid: 'V-277100'
  tag rid: 'SV-277100r1148752_rule'
  tag stig_id: 'APPL-26-002020'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81160r1148751_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
