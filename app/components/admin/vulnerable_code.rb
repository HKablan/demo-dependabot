require 'rails'
require 'devise'
require 'puma'
require 'nokogiri'
require 'rails_admin'
require 'rake'

# Vulnerability 1: Unpatched Rails CSRF Issue
# Rails version 5.2.3 contains a CSRF vulnerability in certain configurations.
class ApplicationController < ActionController::Base
  protect_from_forgery with: :null_session # This weakens CSRF protection
end

# Vulnerability 2: Session Fixation in Devise
# In Devise version 3.5.3, session fixation can occur if proper session handling is not implemented.
class SessionsController < Devise::SessionsController
  def create
    super
    # Vulnerability: session handling issue leading to session fixation
  end
end

# Vulnerability 3: DoS via Puma's connection handling (Puma 3.11.4)
# Older versions of Puma like 3.11.4 can suffer from DoS attacks under heavy load.
def start_server
  Puma::Server.new(lambda { |env| [200, {"Content-Type" => "text/html"}, ["Hello World!"]] }).run
  # Attackers can flood the server with too many connections causing resource exhaustion
end

# Vulnerability 4: XML External Entity (XXE) Injection in Nokogiri 1.8.5
# This vulnerability can allow attackers to access internal files or execute arbitrary code.
def parse_xml_with_nokogiri(xml_data)
  Nokogiri::XML(xml_data) do |config|
    config.noent # This setting allows XXE (XML External Entity) attacks
  end
end

# Vulnerability 5: Insecure Access Control in RailsAdmin 1.2.0
# This version of RailsAdmin has vulnerabilities with unauthorized access to admin pages.
def admin_dashboard
  # Potential CSRF vulnerability and unauthorized access to RailsAdmin interface
  RailsAdmin::Engine.routes.draw do
    get 'admin/dashboard' => 'dashboard#index'
  end
end

# Vulnerability 6: Command Injection in Rake 12.3.0
# Using unsafe user input in Rake tasks can lead to command injection.
def execute_rake_task(task_name, params)
  Rake::Task[task_name].invoke(params)
  # Unsafe handling could allow attackers to inject arbitrary commands
end

# Example usage
begin
  # CSRF vulnerability
  app = ApplicationController.new
  app.create  # Assume this sends a CSRF vulnerable request

  # Session Fixation vulnerability in Devise
  session_controller = SessionsController.new
  session_controller.create  # Vulnerable to session fixation
  
  # Start the server (DoS vulnerability in Puma)
  start_server

  # Example of an XML input leading to XXE attack
  xml_data = "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]> <foo>&xxe;</foo>"
  parse_xml_with_nokogiri(xml_data)

  # Attempt unauthorized access in RailsAdmin
  admin_dashboard

  # Command Injection vulnerability in Rake
  execute_rake_task('db:migrate', '; rm -rf /')  # Dangerous if input is unsanitized
rescue => e
  puts "Caught an error: #{e.message}"
end
