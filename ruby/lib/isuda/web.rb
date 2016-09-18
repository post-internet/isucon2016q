require 'digest/sha1'
require 'digest/md5'
require 'json'
require 'net/http'
require 'uri'

require 'erubis'
require 'mysql2'
require 'mysql2-cs-bind'
require 'rack/utils'
require 'sinatra/base'
require 'tilt/erubis'

require 'dalli'

module Isuda
  class Web < ::Sinatra::Base
    # require 'rack-lineprof'
    # use Rack::Lineprof, profile: 'web.rb'
    enable :protection
    enable :sessions

    set :erb, escape_html: true
    set :public_folder, File.expand_path('../../../../public', __FILE__)

    set :db_user_isuda, ENV['ISUDA_DB_USER'] || 'root'
    set :db_password_isuda, ENV['ISUDA_DB_PASSWORD'] || ''
    set :dsn_isuda, ENV['ISUDA_DSN'] || 'dbi:mysql:db=isuda'

    set :db_user_isutar, ENV['ISUTAR_DB_USER'] || 'root'
    set :db_password_isutar, ENV['ISUTAR_DB_PASSWORD'] || ''
    set :dsn_isutar, ENV['ISUTAR_DSN'] || 'dbi:mysql:db=isutar'

    set :session_secret, 'tonymoris'
    set :isupam_origin, ENV['ISUPAM_ORIGIN'] || 'http://localhost:5050'

    configure :development do
      require 'sinatra/reloader'

      register Sinatra::Reloader
    end

    set(:set_name) do |value|
      condition {
        @user_id = session[:user_id]
        @user_name = session[:user_name]
      }
    end

    set(:authenticate) do |value|
      condition {
        halt(403) unless @user_id
      }
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

      def cache 
        Thread.current[:dalli] ||=
          begin
            dc = Dalli::Client.new('localhost:11211', { namespace: "isuda", compress: true})
            dc
          end
      end

      def register(name, pw)
        chars = [*'A'..'~']
        salt = 1.upto(20).map { chars.sample }.join('')
        salted_password = encode_with_salt(password: pw, salt: salt)
        db_isuda.xquery(%|
          INSERT INTO user (name, salt, password, created_at)
          VALUES (?, ?, ?, NOW())
        |, name, salt, salted_password)
        db_isuda.last_id
      end

      def get_keywords()
        @keywords ||= {}
        if @keywords.empty?
          db_isuda.xquery(%| select keyword, keyword_hash from entry order by character_length(keyword) desc |).map do |k|
            # k[:keyword] = Regexp.escape(k[:keyword])
            # k
            @keywords[k[:keyword]] = k[:keyword_hash]
          end
        end
        @keywords
      end

      def get_user_name(user_id)
        user_name = db_isuda.xquery(%| select name from user where id = ? |, user_id).first[:name]
        halt(403) unless user_name
        user_name
      end

      def get_htmlify_pattern()
        @htmlify_pattern ||= get_keywords().map { |k, v| Regexp.escape(k) }.join('|')
      end

      def clear_keywords_cache()
        @keywords = nil
        @htmlify_pattern = nil
        @keywords_updated = nil
        cache.flush
      end

      def keywords_updated_time()
        @keywords_updated ||= Time.now
      end

      def cache_page()
      
      end

      def encode_with_salt(password: , salt: )
        Digest::SHA1.hexdigest(salt + password)
      end

      def is_spam_content(content)
        isupam_uri = URI(settings.isupam_origin)
        res = Net::HTTP.post_form(isupam_uri, 'content' => content)
        validation = JSON.parse(res.body)
        validation['valid']
        ! validation['valid']
      end

      def htmlify(id, content)
        c = cache.get(id)
        return c if c
        
        keywords = get_keywords
        pattern = get_htmlify_pattern
        kw2hash = {}
        hashed_content = content.gsub(/(#{pattern})/) {|m|
          matched_keyword = $1
          "isuda_#{keywords[matched_keyword]}".tap do |hash|
            kw2hash[matched_keyword] = hash
          end
        }
        escaped_content = Rack::Utils.escape_html(hashed_content)
        kw2hash.each do |(keyword, hash)|
          keyword_url = url("/keyword/#{Rack::Utils.escape_path(keyword)}")
          anchor = '<a href="%s">%s</a>' % [keyword_url, Rack::Utils.escape_html(keyword)]
          escaped_content.gsub!(hash, anchor)
        end
        escaped_content.gsub(/\n/, "<br />\n")
        cache.set(id, escaped_content)
        escaped_content
      end

      def keyword_escape(keyword)
        Regexp.escape(keyword)
      end

      def uri_escape(str)
        Rack::Utils.escape_path(str)
      end

      def redirect_found(path)
        redirect(path, 302)
      end
    end

    get '/initialize' do
      db_isuda.xquery(%| DELETE FROM entry WHERE id > 7101|)
      clear_keywords_cache
      get_keywords
      get_htmlify_pattern
      init_stars

      entries = db_isuda.xquery(%|
        SELECT * FROM entry
        ORDER BY updated_at DESC
        LIMIT 30
      |)
      entries.each do |entry|
        entry[:html] = htmlify(entry[:id], entry[:description])
      end

      content_type :json
      JSON.generate(result: 'ok')
    end

    get '/', set_name: true do
      per_page = 10
      page = (params[:page] || 1).to_i

      entries = db_isuda.xquery(%|
        SELECT * FROM entry
        ORDER BY updated_at DESC
        LIMIT #{per_page}
        OFFSET #{per_page * (page - 1)}
      |)
      entries.each do |entry|
        entry[:html] = htmlify(entry[:id], entry[:description])
        entry[:stars] = get_stars(entry[:keyword])
      end

      total_entries = db_isuda.xquery(%| SELECT count(*) AS total_entries FROM entry |).first[:total_entries].to_i

      last_page = (total_entries.to_f / per_page.to_f).ceil
      from = [1, page - 5].max
      to = [last_page, page + 5].min
      pages = [*from..to]

      locals = {
        entries: entries,
        page: page,
        pages: pages,
        last_page: last_page,
      }
      erb :index, locals: locals
    end

    get '/robots.txt' do
      halt(404)
    end

    get '/register', set_name: true do
      erb :register
    end

    post '/register' do
      name = params[:name] || ''
      pw   = params[:password] || ''
      halt(400) if (name == '') || (pw == '')

      user_id = register(name, pw)
      session[:user_id] = user_id
      session[:user_name] = get_user_name(user_id)

      redirect_found '/'
    end

    get '/login', set_name: true do
      locals = {
        action: 'login',
      }
      erb :authenticate, locals: locals
    end

    post '/login' do
      name = params[:name]
      user = db_isuda.xquery(%| select * from user where name = ? |, name).first
      halt(403) unless user
      halt(403) unless user[:password] == encode_with_salt(password: params[:password], salt: user[:salt])

      session[:user_id] = user[:id]
      session[:user_name] = get_user_name(user[:id])

      redirect_found '/'
    end

    get '/logout' do
      session[:user_id] = nil
      session[:user_name] = nil
      redirect_found '/'
    end

    post '/keyword', set_name: true, authenticate: true do
      keyword = params[:keyword] || ''
      halt(400) if keyword == ''
      description = params[:description]
      halt(400) if is_spam_content(description) || is_spam_content(keyword)

      bound = [@user_id, keyword, description, keyword] * 2
      result = db_isuda.xquery(%|
        INSERT INTO entry (author_id, keyword, description, created_at, updated_at, keyword_hash)
        VALUES (?, ?, ?, NOW(), NOW(), SHA1(?))
        ON DUPLICATE KEY UPDATE
        author_id = ?, keyword = ?, description = ?, updated_at = NOW(), keyword_hash = SHA1(?)
      |, *bound)
      if result == 1
        clear_keywords_cache 
      end

      redirect_found '/'
    end

    get '/keyword/:keyword', set_name: true do
      keyword = params[:keyword] or halt(400)

      entry = db_isuda.xquery(%| select * from entry where keyword = ? |, keyword).first or halt(404)
      entry[:stars] = get_stars(entry[:keyword])
      entry[:html] = htmlify(entry[:id], entry[:description])

      locals = {
        entry: entry,
      }
      erb :keyword, locals: locals
    end

    post '/keyword/:keyword', set_name: true, authenticate: true do
      keyword = params[:keyword] or halt(400)
      is_delete = params[:delete] or halt(400)

      unless db_isuda.xquery(%| SELECT * FROM entry WHERE keyword = ? |, keyword).first
        halt(404)
      end

      db_isuda.xquery(%| DELETE FROM entry WHERE keyword = ? |, keyword)
      get_keywords.delete(keyword_escape(keyword))

      redirect_found '/'
    end

    def init_stars()
      db_isutar.xquery('TRUNCATE star')
    end

    def get_stars(keyword)
      db_isutar.xquery(%| select * from star where keyword = ? |, keyword).to_a
    end

    def post_stars(keyword, user)
      db_isutar.xquery(%|
        INSERT INTO star (keyword, user_name, created_at)
        VALUES (?, ?, NOW())
      |, keyword, user_name)
    end

    get '/stars' do
      stars = get_stars(params[:keyword] || '')
      content_type :json
      JSON.generate(stars: stars)
    end

    post '/stars' do
      keyword = params[:keyword]
      unless db_isuda.xquery(%| SELECT * FROM entry WHERE keyword = ? |, keyword).first
        halt(404)
      end
      post_stars(keyword, param[:user])
      content_type :json
      JSON.generate(result: 'ok')
    end
  end
end
