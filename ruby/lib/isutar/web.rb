require 'json'
require 'net/http'
require 'uri'

require 'mysql2'
require 'mysql2-cs-bind'
require 'rack/utils'
require 'sinatra/base'

module Isutar
  class Web < ::Sinatra::Base
    # require 'rack-lineprof'
    # use Rack::Lineprof, profile: 'web.rb'

    enable :protection

    set :db_user_isuda, ENV['ISUDA_DB_USER'] || 'root'
    set :db_password_isuda, ENV['ISUDA_DB_PASSWORD'] || ''
    set :dsn_isuda, ENV['ISUDA_DSN'] || 'dbi:mysql:db=isuda'

    set :db_user_isutar, ENV['ISUTAR_DB_USER'] || 'root'
    set :db_password_isutar, ENV['ISUTAR_DB_PASSWORD'] || ''
    set :dsn_isutar, ENV['ISUTAR_DSN'] || 'dbi:mysql:db=isutar'

    configure :development do
      require 'sinatra/reloader'

      register Sinatra::Reloader
    end

    helpers do
      def db_isuda
        Thread.current[:db_isuda] ||=
          begin
            _, _, attrs_part = settings.dsn_isuda.split(':', 3)
            attrs = Hash[attrs_part.split(';').map {|part| part.split('=', 2) }]
            mysql = Mysql2::Client.new(
              username: settings.db_user_isuda,
              password: settings.db_password_isuda,
              database: attrs['db'],
              encoding: 'utf8mb4',
              init_command: %|SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'|,
            )
            mysql.query_options.update(symbolize_keys: true)
            mysql
          end
      end

      def db_isutar
        Thread.current[:db_isutar] ||=
          begin
            _, _, attrs_part = settings.dsn_isutar.split(':', 3)
            attrs = Hash[attrs_part.split(';').map {|part| part.split('=', 2) }]
            mysql = Mysql2::Client.new(
              username: settings.db_user_isutar,
              password: settings.db_password_isutar,
              database: attrs['db'],
              encoding: 'utf8mb4',
              init_command: %|SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'|,
            )
            mysql.query_options.update(symbolize_keys: true)
            mysql
          end
      end
    end

    get '/stars' do
      keyword = params[:keyword] || ''
      stars = db_isutar.xquery(%| select * from star where keyword = ? |, keyword).to_a

      content_type :json
      JSON.generate(stars: stars)
    end

    post '/stars' do
      keyword = params[:keyword]

      unless db_isuda.xquery(%| SELECT * FROM entry WHERE keyword = ? |, keyword).first
        halt(404)
      end

      user_name = params[:user]
      db_isutar.xquery(%|
        INSERT INTO star (keyword, user_name, created_at)
        VALUES (?, ?, NOW())
      |, keyword, user_name)

      content_type :json
      JSON.generate(result: 'ok')
    end
  end
end
