# frozen_string_literal: true

# State of a launchd job in the system domain.
class MacosLaunchdService < Inspec.resource(1)
  name 'macos_launchd_service'
  supports platform: 'darwin'
  desc 'Whether a system launchd job is loaded and whether it carries a disabled/enabled override.'
  example <<~EXAMPLE
    describe macos_launchd_service('com.apple.smbd') do
      it { should be_disabled }
      it { should_not be_loaded }
    end
  EXAMPLE

  def initialize(label)
    @label = label
  end

  # The job is currently bootstrapped in the system domain.
  def loaded?
    inspec.command("/bin/launchctl print system/#{@label}").exit_status.zero?
  end

  # `launchctl print-disabled system` lists the job as disabled.
  def disabled?
    %w[disabled true].include?(override)
  end

  # `launchctl print-disabled system` lists the job as explicitly enabled.
  def enabled?
    %w[enabled false].include?(override)
  end

  # Raw override value ("disabled", "enabled", or nil when no override exists).
  def override
    line = inspec.command('/bin/launchctl print-disabled system').stdout.lines.find do |l|
      l.include?("\"#{@label}\" =>")
    end
    line&.split('=>')&.last&.strip
  end

  def to_s
    "launchd system/#{@label}"
  end
end
