control 'SV-277168' do
  title 'The macOS system must configure the login window to prompt for username and password.'
  desc "The login window must be configured to prompt all users for both a username and a password.

By default, the system displays a list of known users on the login window, which can make it easier for a malicious user to gain access to someone else's account. Requiring users to type in both their username and password mitigates the risk of unauthorized users gaining access to the information system."
  desc 'check', %q(Verify the macOS system is configured to prompt for username and password at the login window with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('SHOWFULLNAME').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to prompt for username and password at the login window by installing the "com.apple.loginwindow" configuration profile.'
  impact 0.5
  tag check_id: 'C-81323r1148954_chk'
  tag severity: 'medium'
  tag gid: 'V-277168'
  tag rid: 'SV-277168r1148956_rule'
  tag stig_id: 'APPL-26-005052'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-81228r1148955_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

  describe macos_managed_preference('com.apple.loginwindow', 'SHOWFULLNAME') do
    its('value') { should eq true }
  end
end
