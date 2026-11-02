control 'SV-277185' do
  title 'The macOS system must install security-relevant software updates within 30 days unless the time period is directed by an authoritative source (e.g., IAVM, CTOs, DTMs, STIGs).'
  desc 'Security flaws with operating systems are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.'
  desc 'check', %q(Verify security-relevant software updates are installed on the operating system within 30 days with the following command:

softwareupdate_date_epoch=$(/bin/date -j -f "%Y-%m-%d" "$(/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist LastFullSuccessfulDate | /usr/bin/awk '{print $1}')" "+%s")
thirty_days_epoch=$(/bin/date -v -30d "+%s")
if [[ $softwareupdate_date_epoch -lt $thirty_days_epoch ]]; then
/bin/echo "0"
else
/bin/echo "1"
fi

If the result is not "1", this is a finding.)
  desc 'fix', "Install the latest updates within 30 days unless the time period is directed by an authoritative source (e.g., IAVM, CTOs, DTMs, STIGs).
https://support.apple.com/en-us/108382 

If enrolled in an MDM, consult the MDM's documentation for automated methods."
  impact 0.7
  tag check_id: 'C-81340r1184564_chk'
  tag severity: 'high'
  tag gid: 'V-277185'
  tag rid: 'SV-277185r1186397_rule'
  tag stig_id: 'APPL-26-999999'
  tag gtitle: 'SRG-OS-000439-GPOS-00195'
  tag fix_id: 'F-81245r1186396_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']

  last_check = command('/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist LastFullSuccessfulDate').stdout.strip
  now = command('/bin/date +%s').stdout.to_i
  days_since_update = begin
    (now - Time.parse(last_check).to_i) / 86_400
  rescue ArgumentError
    nil
  end

  describe "Days since the last successful software update (LastFullSuccessfulDate: #{last_check.empty? ? 'not set' : last_check})" do
    subject { days_since_update }
    it { should_not be_nil }
    it { should cmp <= 30 }
  end
end
