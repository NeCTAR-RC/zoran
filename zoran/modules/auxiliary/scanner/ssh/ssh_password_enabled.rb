##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'logger'

require 'msf/core'
require 'net/ssh'
require 'net/ssh/transport/session'
require 'net/ssh/authentication/session'
require 'net/ssh/connection/session'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell

  attr_accessor :ssh_socket, :good_credentials

  def initialize
    super(
      'Name'        => 'SSH Login Check Scanner',
      'Description' => %q{
        This module will test ssh logins on a range of machines and
        report successful logins.  If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
      },
      'Author'      => ['todb'],
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(22)
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )

    deregister_options('RHOST')

    @good_credentials = {}

  end

  def rport
    datastore['RPORT']
  end

  def do_login(ip,user,pass,port)
    opt_hash = {
      :auth_methods  => ['password','keyboard-interactive'],
      :msframework   => framework,
      :msfmodule     => self,
      :port          => port,
      :disable_agent => true,
      :password      => pass,
      :config        => false,
      :verbose       => Logger::DEBUG,
      :proxies       => datastore['Proxies']
    }

    opt_hash.merge!(:verbose => :debug) if datastore['SSH_DEBUG']

    begin
      ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
          transport = Net::SSH::Transport::Session.new(ip, opt_hash)
          auth = Net::SSH::Authentication::Session.new(transport, opt_hash)
          user = options.fetch(:user, user)
          auth.authenticate("ssh-connection", user, options[:password])
          if auth.allowed_auth_methods.include?('password') or auth.allowed_auth_methods.include?('keyboard-interactive')
            return :success
          end
      end
    rescue ::Timeout::Error
      return :connection_disconnect
    rescue Net::SSH::Exception
      return :fail  # For whatever reason. Can't tell if passwords are on/off without timing responses.
    end
    return :fail
  end

  def do_report(ip,port)
    service = report_service(:host => ip, :port => port, 
                             :name => "ssh", :proto => "tcp")
    report_note(
      :host => ip,
      :service => service,
      :port => port,
      :proto => 'tcp',
      :type => 'ssh_password_auth',
      :data => 'true'
      )
  end

  def run_host(ip)
    ret = nil
    select(nil,nil,nil,1)
    ret = do_login(ip,'root','',rport)
    case ret
    when :success
      print_status("#{ip} Password auth is enabled")
      do_report(ip,rport)
    when :connection_error
      print_error("Could not connect")
      :abort
    when :connection_disconnect
      print_error("Connection timed out")
      :abort
    end
  end

end
