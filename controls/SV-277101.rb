control 'SV-277101' do
  title 'The macOS system must disable sending diagnostic and usage data to Apple.'
  desc 'The ability to submit diagnostic data to Apple must be disabled.

The information system must be configured to provide only essential capabilities. Disabling the submission of diagnostic and usage information will mitigate the risk of unwanted data being sent to Apple.

'
  desc 'check', %q(Verify the macOS system is configured to disable sending diagnostic and usage data to Apple with the following command:

/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.SubmitDiagInfo')\
.objectForKey('AutoSubmit').js
let pref2 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowDiagnosticSubmission').js
if ( pref1 == false && pref2 == false ){
    return("true")
} else {
    return("false")
}
}
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable sending diagnostic and usage data to Apple by installing the "com.apple.SubmitDiagInfo" configuration profile.'
  impact 0.5
  tag check_id: 'C-81256r1148753_chk'
  tag severity: 'medium'
  tag gid: 'V-277101'
  tag rid: 'SV-277101r1148755_rule'
  tag stig_id: 'APPL-26-002021'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-81161r1148754_fix'
  tag satisfies: ['SRG-OS-000205-GPOS-00083', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-001312', 'CCI-001314']
  tag nist: ['SI-11 a', 'SI-11 b']
end
