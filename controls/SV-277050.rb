control 'SV-277050' do
  title "The macOS system must disable login to other users' active and locked sessions."
  desc %q(The ability to log in to another user's active or locked session must be disabled.

WARNING: This rule may cause issues when platformSSO is configured.

macOS has a privilege that can be granted to any user that will allow that user to unlock active users' sessions. Disabling the administrator's and/or user's ability to log in to another user's active and locked session prevents unauthorized people from viewing potentially sensitive and/or personal information.

Note: Configuring this setting will change the user experience and disable TouchID from unlocking the screen saver. To restore the user experience and allow TouchID to unlock the screen saver, run "/usr/bin/sudo /usr/bin/defaults write /Library/Preferences/com.apple.loginwindow screenUnlockMode -int 1". This setting can also be deployed with a configuration profile.

)
  desc 'check', %q(Verify the macOS system is configured to disable login to other users' active and locked sessions with the following command:

RESULT="FAIL"
  SS_RULE=$(/usr/bin/security -q authorizationdb read system.login.screensaver  2>&1 | /usr/bin/xmllint --xpath "//dict/key[.='rule']/following-sibling::array[1]/string/text()" -)

  if [[ "${SS_RULE}" == "authenticate-session-owner" ]]; then
      RESULT="PASS"
  else
      PSSO_CHECK=$(/usr/bin/security -q authorizationdb read "$SS_RULE"  2>&1 | /usr/bin/xmllint --xpath '//key[.="rule"]/following-sibling::array[1]/string/text()' -)
      if /usr/bin/grep -Fxq "authenticate-session-owner" <<<"$PSSO_CHECK"; then
          RESULT="PASS"
      fi
  fi

  echo $RESULT

If the result is not "PASS", this is a finding.)
  desc 'fix', %q(Configure the macOS system to disable login to other users' active and locked sessions with the following command:

SS_RULE=$(/usr/bin/security -q authorizationdb read system.login.screensaver 2>&1 | /usr/bin/xmllint --xpath "//dict/key[.='rule']/following-sibling::array[1]/string/text()" -)

  if [[ "$SS_RULE" == *psso* ]]; then
      /usr/bin/security -q authorizationdb read psso-screensaver > "/tmp/psso-screensaver-mscp.plist"
      /usr/bin/sed -i.bak 's/<string>authenticate-session-owner-or-admin<\/string>/<string>authenticate-session-owner<\/string>/' /tmp/psso-screensaver-mscp.plist
      /usr/bin/security -q authorizationdb write psso-screensaver-mscp < /tmp/psso-screensaver-mscp.plist
      /usr/bin/security -q authorizationdb write system.login.screensaver psso-screensaver-mscp 2>&1
  else
      /usr/bin/security -q authorizationdb write system.login.screensaver "authenticate-session-owner" 2>&1
  fi)
  impact 0.5
  tag check_id: 'C-81205r1149330_chk'
  tag severity: 'medium'
  tag gid: 'V-277050'
  tag rid: 'SV-277050r1149393_rule'
  tag stig_id: 'APPL-26-000090'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-81110r1149331_fix'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000109-GPOS-00056']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-004045']
  tag nist: ['IA-2', 'IA-2 (5)']

  screensaver_rules = macos_authorizationdb('system.login.screensaver').rules
  effective_rules = screensaver_rules + screensaver_rules.flat_map { |rule| macos_authorizationdb(rule).rules }

  describe 'Rules for the system.login.screensaver right (including delegated rules)' do
    subject { effective_rules }
    it { should include 'authenticate-session-owner' }
  end
end
