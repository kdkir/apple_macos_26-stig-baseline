# frozen_string_literal: true

# Settings from the BSM audit configuration file /etc/security/audit_control.
class MacosAuditControl < Inspec.resource(1)
  name 'macos_audit_control'
  supports platform: 'darwin'
  desc 'Parsed values from /etc/security/audit_control.'
  example <<~EXAMPLE
    describe macos_audit_control do
      its('flags') { should include 'lo' }
      its('expire_after') { should cmp '7d' }
    end
  EXAMPLE

  PATH = '/etc/security/audit_control'

  def initialize(path = PATH)
    @path = path
  end

  def exist?
    inspec.file(@path).exist?
  end

  # Values of the last "flags:" line, split on commas.
  def flags
    value('flags').to_s.split(',').map(&:strip).reject(&:empty?)
  end

  # Audit log directories ("dir:" lines).
  def dirs
    entries('dir')
  end

  def dir
    dirs.first
  end

  def minfree
    value('minfree')
  end

  def expire_after
    value('expire-after')
  end

  def value(name)
    entries(name).last
  end

  def to_s
    @path
  end

  private

  def entries(name)
    content.lines.map(&:strip).grep(/\A#{Regexp.escape(name)}:/).map { |l| l.split(':', 2).last.strip }
  end

  def content
    @content ||= inspec.file(@path).content.to_s
  end
end
