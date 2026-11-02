control 'SV-277181' do
  title 'The macOS system must enforce installation of XProtect Remediator and Gatekeeper updates automatically.'
  desc 'Software Update must be configured to update XProtect Remediator and Gatekeeper automatically.

This setting enforces definition updates for XProtect Remediator and Gatekeeper. With this setting in place, new malware and adware that Apple has added to the list of malware or untrusted software will not execute. These updates do not require the computer to be restarted.

https://support.apple.com/en-us/HT207005

Note: Software update will automatically update XProtect Remediator and Gatekeeper by default in the macOS.'
  desc 'check', %q(Verify the macOS system is configured to enforce installation of XProtect Remediator and Gatekeeper updates automatically with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('ConfigDataInstall').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to enforce installation of XProtect Remediator and Gatekeeper updates automatically by installing the "com.apple.SoftwareUpdate" configuration profile.'
  impact 0.5
  tag check_id: 'C-81336r1148993_chk'
  tag severity: 'medium'
  tag gid: 'V-277181'
  tag rid: 'SV-277181r1268251_rule'
  tag stig_id: 'APPL-26-005130'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-81241r1148994_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe macos_managed_preference('com.apple.SoftwareUpdate', 'ConfigDataInstall') do
    its('value') { should eq true }
  end
end
