#!/usr/bin/env bash
# -*- mode: ruby; -*-
# copyright (c) 2019 by Andrei Borac
# released under the MIT license, for details see the LICENSE file

# the header below is valid bash script as well as valid Ruby code
NIL2=\
=begin
exec env -i PATH="$(echo /{usr/{local/,},}{s,}bin | tr ' ' ':')" DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" ruby -E BINARY:BINARY -I . -e 'load("'"$0"'");' -- "$@"
=end
nil;

require("open3");

require("digest");
require("openssl");

# generally aiming for 128-bit equivalent security
# 8192-bit prime from https://tools.ietf.org/html/rfc3526

G=2
P="   FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
      43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
      88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
      2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
      287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
      1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
      93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
      36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD
      F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831
      179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B
      DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF
      5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6
      D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3
      23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
      CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328
      06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C
      DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE
      12BF2D5B 0B7474D6 E694F91E 6DBE1159 74A3926F 12FEE5E4
      38777CB6 A932DF8C D8BEC4D0 73B931BA 3BC832B6 8D9DD300
      741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C 5AE4F568
      3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9
      22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B
      4BCBC886 2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A
      062B3CF5 B3A278A6 6D2A13F8 3F44F82D DF310EE0 74AB6A36
      4597E899 A0255DC1 64F31CC5 0846851D F9AB4819 5DED7EA1
      B1D510BD 7EE74D73 FAF36BC3 1ECFA268 359046F4 EB879F92
      4009438B 481C6CD7 889A002E D5EE382B C9190DA6 FC026E47
      9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71
      60C980DD 98EDD3DF FFFFFFFF FFFFFFFF".split.join.to_i(16);

def itobig(x)
  out = [];
  
  while (x > 0)
    out << (x % 256);
    x /= 256;
  end
  
  return out.map{|x| x.chr; }.reverse.join;
end

def bigtoi(str)
  return str.bytes.inject(0){|s, i| ((s << 8) + i); };
end

def drygest(data)
  return bigtoi(Digest::SHA256.digest(data));
end

def kdf(phrase)
  out = Digest::SHA256.digest(phrase);
  
  1000000.times{
    out = Digest::SHA256.digest((phrase + out));
  };
  
  return bigtoi(out);
end

def pinentry()
  stdout, stderr, status, = Open3.capture3("bash", "-c", "set -o xtrace ; ( echo GETPIN ; echo BYE ) | pinentry-gnome3");
  
  raise if (!(status.success?));
  
  raise if (!(stdout.lines.length == 4));
  raise if (!(stdout.lines[0] == "OK Pleased to meet you\n"));
  raise if (!(stdout.lines[1][0..1] == "D "));
  raise if (!(stdout.lines[1][-1] == "\n"));
  raise if (!(stdout.lines[2] == "OK\n"));
  
  return stdout.lines[1][2..-2];
end

COMMON_FUNCTIONS = '
set -o xtrace
set -o errexit
set -o nounset
set -o pipefail

function target()
{
  mkdir -p ./.gitcrypto/tmp
  
  if sudo mountpoint -q ./.gitcrypto/tmp
  then
    if [ "${1-}" == "fresh" ]
    then
      sudo umount ./.gitcrypto/tmp
      
      if sudo mountpoint -q ./.gitcrypto/tmp
      then
        exit 1
      fi
      
      sudo mount -t tmpfs none ./.gitcrypto/tmp
    fi
  else
    sudo mount -t tmpfs none ./.gitcrypto/tmp
  fi
  
  mkdir -p ./.gitcrypto/tmp/{bundle,review,export,rescue}
}

function git_repack_all()
{
  fn=./.VOY2EnPHzhKUQb8z
  git cat-file --batch-check --batch-all-objects | egrep -o "^[0-9a-f]{40}" >"$fn"
  mkdir -p ./.git/objects/newpack
  cat "$fn" | git pack-objects ./.git/objects/newpack/pack
  rm -f "$fn"
  rm -f ./.git/objects/pack/pack-*
  mv ./.git/objects/newpack/* ./.git/objects/pack/
  rmdir ./.git/objects/newpack
}

function recover_to_from()
{
  to="$1"
  from="$2"
  
  (
    cd "$to"
    
    git init
    
    lastref=
    i=1000000000
    while [ -f "$from"/"$i".bundle ]
    do
      lastref="$(git bundle unbundle "$from"/"$i".bundle | cut -d " " -f 1)"
      git tag -f gitcrypto-focal-point "$lastref"
      if [ "$(( (i % 1000) ))" == "0" ]
      then
        git_repack_all
      fi
      i="$(( (i+1) ))"
    done
    git tag -d gitcrypto-focal-point || true
    
    if [ "$lastref" != "" ]
    then
      git branch master "$lastref"
      git_repack_all
    fi
  )
}
'

def main()
  if (ARGV[0] == "keygen")
    raise if (!(system("bash", "-c", COMMON_FUNCTIONS + '
[ -d ./.git ]

mkdir -p ./.gitcrypto/cfg
')));
    
    phrase = pinentry;
    
    a = kdf(phrase);
    
    ga = G.to_bn.mod_exp(a, P).to_i;
    
    IO.write("./.gitcrypto/cfg/pubkey", itobig(ga));
  end
  
  if (ARGV[0] == "trykey")
    phrase = pinentry;
    
    a = kdf(phrase);
    
    ga = G.to_bn.mod_exp(a, P).to_i;
    
    raise if (!(ga == bigtoi(IO.read("./.gitcrypto/cfg/pubkey"))));
  end
  
  if (ARGV[0] == "backup")
    raise if (!(system("bash", "-c", COMMON_FUNCTIONS + '
[ -d ./.git ]

ORIGINAL_HEAD_HASH="$(git rev-parse --verify HEAD)"

target fresh

function emit_parents()
{
  git cat-file -p "$1" |\
      (
        parents=()
        cparents=()
        
        while read line
        do
          if [ "${line:0:7}" == "parent " ]
          then
            parents+=("${line:7}")
            cparents+=("^${line:7}")
          fi
          
          if [ "${line:0:7}" == "author " ]
          then
            break
          fi
        done
        
        cat >/dev/null
        
        declare -p parents
        declare -p cparents
      )
}

git log --full-history --date-order --reverse --format=format:"%H"$'"'"'\n'"'"' | sed -e '"'"'/^$/d'"'"' |\
    (
      i=1000000000
      while read hash
      do
        eval "$(emit_parents "$hash")"
        git tag -f gitcrypto-focal-point "$hash"
        git bundle create ./.gitcrypto/tmp/bundle/"$i".bundle gitcrypto-focal-point "${cparents[@]}"
        i="$(( (i+1) ))"
      done
      git tag -d gitcrypto-focal-point || true
    )

recover_to_from ./.gitcrypto/tmp/review ./../bundle

RESTORE_HEAD_HASH="$(git rev-parse --verify HEAD)"

[ "$RESTORE_HEAD_HASH" == "$ORIGINAL_HEAD_HASH" ]
')));
    
    $stderr.puts("encrypting ...");
    
    ga = bigtoi(IO.read("./.gitcrypto/cfg/pubkey"));
    
    1.times{
      i = 1000000000;
      fn = nil;
      
      while (File.exists?((fn = "./.gitcrypto/tmp/bundle/#{i}.bundle")))
        payload = IO.read(fn);
        
        b = drygest(payload);
        gb = G.to_bn.mod_exp(b, P).to_i;
        IO.write("./.gitcrypto/tmp/export/#{i}.key", itobig(gb));
        
        sym = Digest::SHA256.digest(itobig(ga.to_bn.mod_exp(b, P).to_i));
        
        cipher = OpenSSL::Cipher.new("aes-256-ctr");
        cipher.encrypt;
        cipher.iv = "0"*16;
        cipher.key = sym;
        
        IO.write("./.gitcrypto/tmp/export/#{i}.enc", (cipher.update(payload) + cipher.final));
        
        i += 1;
      end
    };
    
    $stderr.puts("encrypted");
  end
  
  if (ARGV[0] == "rescue")
    raise if (!(system("bash", "-c", COMMON_FUNCTIONS + '
target preserve

[ ! -d ./.git ]
')));
    
    $stderr.puts("decrypting ...");
    
    phrase = pinentry;
    
    a = kdf(phrase);
    
    1.times{
      i = 1000000000;
      fnk = nil;
      fne = nil;
      
      while (File.exists?((fnk = (ARGV[1] + "/#{i}.key"))) && File.exists?((fne = (ARGV[1] + "/#{i}.enc"))))
        $stderr.puts("i=#{i}");
        
        gb = bigtoi(IO.read(fnk));
        
        sym = Digest::SHA256.digest(itobig(gb.to_bn.mod_exp(a, P).to_i));
        
        cipher = OpenSSL::Cipher.new("aes-256-ctr");
        cipher.decrypt;
        cipher.iv = "0"*16;
        cipher.key = sym;
        
        payload = (cipher.update(IO.read(fne)) + cipher.final);
        
        b = drygest(payload);
        gb2 = G.to_bn.mod_exp(b, P).to_i;
        
        raise if (!(gb2 == gb));
        
        IO.write("./.gitcrypto/tmp/rescue/#{i}.bundle", payload);
        
        i += 1;
      end
    };
    
    $stderr.puts("decrypted");
    
    raise if (!(system("bash", "-c", COMMON_FUNCTIONS + '
recover_to_from . ./.gitcrypto/tmp/rescue
')));
  end
end

main;
puts("+OK (gitcrypto.rb)");
