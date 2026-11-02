control 'SV-277123' do
  title 'The macOS system must require an administrator password to modify systemwide preferences.'
  desc 'The system must be configured to require an administrator password to modify the systemwide preferences in System Settings.

Some Preference Panes in System Settings contain settings that affect the entire system. Requiring a password to unlock these systemwide settings reduces the risk of an unauthorized user modifying system configurations.'
  desc 'check', %q(Verify the macOS system is configured to require administrator privileges to modify systemwide settings with the following command:

authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")
result="1"
for section in ${authDBs[@]}; do
if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "shared")]/following-sibling::*[1])' -) != "false" ]]; then
result="0"
fi
if [[ $(security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath '//*[contains(text(), "group")]/following-sibling::*[1]/text()' - ) != "admin" ]]; then
result="0"
fi
if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "authenticate-user")]/following-sibling::*[1])' -) != "true" ]]; then
result="0"
fi
if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "session-owner")]/following-sibling::*[1])' -) != "false" ]]; then
result="0"
fi
done
echo $result

If the result is not "1", this is a finding.)
  desc 'fix', 'Configure the macOS system to require administrator privileges to modify systemwide settings with the following command:

authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")

for section in ${authDBs[@]}; do
/usr/bin/security -q authorizationdb read "$section" > "/tmp/$section.plist"

class_key_value=$(usr/libexec/PlistBuddy -c "Print :class" "/tmp/$section.plist" 2>&1)
if [[ "$class_key_value" == *"Does Not Exist"* ]]; then
/usr/libexec/PlistBuddy -c "Add :class string user" "/tmp/$section.plist"
else
/usr/libexec/PlistBuddy -c "Set :class user" "/tmp/$section.plist"
fi

key_value=$(/usr/libexec/PlistBuddy -c "Print :shared" "/tmp/$section.plist" 2>&1)  
if [[ "$key_value" == *"Does Not Exist"* ]]; then
/usr/libexec/PlistBuddy -c "Add :shared bool false" "/tmp/$section.plist"
else
/usr/libexec/PlistBuddy -c "Set :shared false" "/tmp/$section.plist"
fi

auth_user_key=$(/usr/libexec/PlistBuddy -c "Print :authenticate-user" "/tmp/$section.plist" 2>&1)  
if [[ "$auth_user_key" == *"Does Not Exist"* ]]; then
/usr/libexec/PlistBuddy -c "Add :authenticate-user bool true" "/tmp/$section.plist"
else
/usr/libexec/PlistBuddy -c "Set :authenticate-user true" "/tmp/$section.plist"
fi

session_owner_key=$(/usr/libexec/PlistBuddy -c "Print :session-owner" "/tmp/$section.plist" 2>&1)  
if [[ "$session_owner_key" == *"Does Not Exist"* ]]; then
/usr/libexec/PlistBuddy -c "Add :session-owner bool false" "/tmp/$section.plist"
else
/usr/libexec/PlistBuddy -c "Set :session-owner false" "/tmp/$section.plist"
fi

group_key=$(usr/libexec/PlistBuddy -c "Print :group" "/tmp/$section.plist" 2>&1)
if [[ "$group_key" == *"Does Not Exist"* ]]; then
/usr/libexec/PlistBuddy -c "Add :group string admin" "/tmp/$section.plist"
else
/usr/libexec/PlistBuddy -c "Set :group admin" "/tmp/$section.plist"
fi

/usr/bin/security -q authorizationdb write "$section" < "/tmp/$section.plist"
done'
  impact 0.7
  tag check_id: 'C-81278r1148819_chk'
  tag severity: 'high'
  tag gid: 'V-277123'
  tag rid: 'SV-277123r1148821_rule'
  tag stig_id: 'APPL-26-002069'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-81183r1148820_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
