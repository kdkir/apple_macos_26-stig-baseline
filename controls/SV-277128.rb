control 'SV-277128' do
  title 'The macOS system must disable AppleID and internet Account Modification.'
  desc 'The system must disable Account Modification. 

Account Modification includes adding or modifying internet accounts in Apple Mail, Calendar, or Contacts in the Internet Account System Setting Pane or the AppleID System Setting Pane.

This prevents the addition of unauthorized accounts.

[IMPORTANT]
====
Some organizations may allow the use and configuration of the built-in Mail.app, Calendar.app, and Contacts.app for organizational communication. Information system security officers (ISSOs) may make the risk-based decision not to disable the Internet Accounts System Preference pane to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
===='
  desc 'check', %q(Verify the macOS system is configured to disable account modification with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAccountModification').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Account Modification by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81283r1148834_chk'
  tag severity: 'medium'
  tag gid: 'V-277128'
  tag rid: 'SV-277128r1148836_rule'
  tag stig_id: 'APPL-26-002120'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81188r1148835_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowAccountModification') do
    its('value') { should eq false }
  end
end
