control 'SV-277056' do
  title 'The macOS system must enforce auto logout after 86400 seconds of inactivity.'
  desc "Auto logout must be configured to automatically terminate a user session and log out after 86400 seconds of inactivity.

Note: The maximum that macOS can be configured for autologoff is 86400 seconds.

[IMPORTANT]
====
The automatic logout may cause disruptions to an organization's workflow and/or loss of data. Information system security officers (ISSOs) are advised to first fully weigh the potential risks posed to their organization before opting to disable the automatic logout setting.
===="
  desc 'check', %q(Verify the macOS system is configured to enforce auto logout after 86400 seconds of inactivity with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('.GlobalPreferences')\
.objectForKey('com.apple.autologout.AutoLogOutDelay').js
EOS

If the result is not "86400", this is a finding.)
  desc 'fix', 'Configure the macOS system to enforce auto logout after 86400 seconds of inactivity by installing the "com.apple.GlobalPreferences" configuration profile.'
  impact 0.5
  tag check_id: 'C-81211r1148618_chk'
  tag severity: 'medium'
  tag gid: 'V-277056'
  tag rid: 'SV-277056r1148620_rule'
  tag stig_id: 'APPL-26-000160'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-81116r1148619_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']

  describe macos_managed_preference('.GlobalPreferences', 'com.apple.autologout.AutoLogOutDelay') do
    its('value') { should eq 86400 }
  end
end
