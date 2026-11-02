control 'SV-277099' do
  title 'The macOS system must disable the camera.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect from collaborative computing devices (i.e., cameras) can result in subsequent compromises of organizational information. Providing easy methods to physically disconnect from such devices after a collaborative computing session helps to ensure that participants carry out the disconnect activity without having to go through complex and tedious procedures.'
  desc 'check', %q(If the device or operating system does not have a camera installed, this requirement is not applicable.

This requirement is not applicable to mobile devices (smartphones and tablets), where the use of the camera is a local authorizing official (AO) decision.

This requirement is not applicable to dedicated video teleconference (VTC) suites in approved VTC locations that are centrally managed.

For an external camera, if there is not a method for the operator to manually disconnect camera at the end of collaborative computing sessions, this is a finding.

For a built-in camera, the camera must be protected by a camera cover (e.g., laptop camera cover slide) when not in use. 

If the built-in camera is not protected with a camera cover or is not physically disabled, this is a finding.

If the camera is not disconnected, covered, or physically disabled, verify the macOS system is configured to disable the camera with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCamera').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable the camera by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81254r1148747_chk'
  tag severity: 'medium'
  tag gid: 'V-277099'
  tag rid: 'SV-277099r1148749_rule'
  tag stig_id: 'APPL-26-002017'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81159r1148748_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  camera_protected = input('camera_physically_protected')

  if !input('camera_installed')
    impact 0.0
    describe 'Camera (input camera_installed)' do
      skip 'No camera is installed; this requirement is not applicable.'
    end
  elsif camera_protected
    describe 'Camera is covered, disconnected, or physically disabled (attested via input camera_physically_protected)' do
      subject { camera_protected }
      it { should eq true }
    end
  else
    describe macos_managed_preference('com.apple.applicationaccess', 'allowCamera') do
      its('value') { should eq false }
    end
  end
end
