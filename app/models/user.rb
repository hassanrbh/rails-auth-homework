# == Schema Information
#
# Table name: users
#
#  id              :integer          not null, primary key
#  username        :string           not null
#  password_digest :string           not null
#  session_token   :string           not null
#  created_at      :datetime         not null
#  updated_at      :datetime         not null
#
class User < ApplicationRecord
    attr_reader :password

    validates :username, presence: true
    validates :session_token, presence: true
    validates :password_digest, presence: {message: 'Pasword can\'t be blank'}
    validates :password, length: {minimum: 6, message: 'Password must be at least 6 characters', allow_nil: true}
    before_validation :ensure_session_token

    # write ::find_by_credentials that fetch the user in the DB
    def self.find_by_credentials(username,password)
        user = User.find_by(:username => username)
        return nil if user.nil?
        user.is_password!(password) ? user : nil
    end

    # generate a session token
    def self.generate_session_token
        SecureRandom::urlsafe_base64(16)
    end

    # check the length of the password and set password_digest to a hash pass
    def password=(password)
        @password = password
        self.password_digest = BCrypt::Password.create(password)
    end

    # check if the password is for that user
    def is_password!(password)
        BCrypt::Password.new(self.password_digest).is_password?(password)
    end

    # reset the currently session_token
    def reset_session_token!
        self.session_token = self.class.generate_session_token
        self.save!
    end



    private

    def ensure_session_token
        self.session_token ||= self.class.generate_session_token
    end
end
