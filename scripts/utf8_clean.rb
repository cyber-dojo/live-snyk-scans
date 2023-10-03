# frozen_string_literal: true

def utf8_clean(str)
# force an encoding change - if encoding is already utf-8
# then encoding to utf-8 is a no-op and invalid byte
# sequences are not detected.
str = str.encode('UTF-16', 'UTF-8', invalid: :replace, replace: '')
str.encode('UTF-8', 'UTF-16')
end

# http://robots.thoughtbot.com/fight-back-utf-8-invalid-byte-sequences
