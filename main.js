//khai báo khóa
var alpha,beta,a,k;
var p = null;

//khai báo biến bản rõ, bản mã
var encrypt_banro;
var encrypt_banma_gamma = null;
var encrypt_banma_delta =null;
var decrypt_banro;
var decrypt_banma;
var crypto_string;
var crypto_hash;



//Hàm trả về ước chung lớn nhất của 2 số
function gcd(a, b) {
    while (b !== 0) {
      const temp = b;
      b = a % b;
      a = temp;
    }
    return a;
}
//Hàm kiểm tra xem 2 số có ước chung lớn nhất là 1 hay không
function isCoprime(a, b) {
    return gcd(a, b) === 1;
}

//hàm tính (a ^b) mod c
function modPow(base, exp, modul) {
    let t = 1;
    while(exp>0)
    {
        if(exp % 2 !== 0)
        {
          t = (t * base)% modul;
        }

        base = (base * base) % modul;
        exp = Math.floor(exp/2);
    }
    return t % modul;
}


//Hàm tim phần tử sinh trong Zp
function findPrimitiveRoot(p) {
    //duyệt alpha từ 2 đến p -1
    for (let g = 2; g < p; g++) {
      console.log(g);
      let isPrimitiveRoot = true;
      //duyệt khóa bí mật a từ 1 đến p-1
      for (let i = 1; i < p - 1; i++) {
        if (modPow(g, i, p) === 1) {
          isPrimitiveRoot = false; //nếu với 1 giá trị a bất kì khiến modPow(alpha,a,p) = 1 --> loại alpha
          break;
        }
      }
      if (isPrimitiveRoot) {
        return g; //nếu đạt điều kiện trả về phân tử sinh
      }
    }
    return -1; // Trả về -1 nếu không tìm thấy phần tử nguyên thủy
  }

//Ham kiem tra xem co phai so nguyen to hay khong
function isPrime(num) {
    if (num < 2) {
      return false;
    }
    //Duyệt từ 2 đến căn bậc 2 của số, nếu chia hết trả về false
    for (let i = 2; i <= Math.sqrt(num); i++) {
      if (num % i === 0) {
        return false;
      }
    }
    //nếu không chia hết trả về True
    return true;
}

//Hàm chọn random số nguyên tố từ 1000 đến 10.000 
function generatePrimeNumber() {
    let randomPrime;
    do {
      randomPrime = Math.floor(Math.random() * 2000 + 1000);
    } while (!isPrime(randomPrime));//tiếp tục random đến khi nào là số nguyên tố thì trả về số nguyên tố
    return randomPrime;
}

//Hàm chọn khóa private ngẫu nhiên từ 2 đến (p-2)
function generatePrivateKey(p) {
    return Math.floor(Math.random() * (p - 4) + 2);
}
//Hàm chọn khóa k từ 1 đến p -2 với điều kiện k và p có ước chung lớn nhất bằng 1
function chooseK(p) {
    let key;
    do {
      key = Math.floor(Math.random() * (p - 3) + 1);
    } while (!isCoprime(key, p-1));
    return key;
}

//Hàm đọc file word từ người dùng
function readFile(inputTagId,outPutTextBox){
    $(inputTagId).change(function(e) {
        var file = e.target.files[0];

        if (file) {
          var reader = new FileReader();

          reader.onload = function(e) {
            var arrayBuffer = e.target.result;

            var options = {
              arrayBuffer: arrayBuffer
            };

            mammoth.extractRawText(options)
              .then(function(result) {
                var text = result.value;
                var content = text;
                encrypt_banro = content;
                $(outPutTextBox).val(content);
            })
            .catch(function(error) {
                console.log(error);
            });
            
          };

          reader.readAsArrayBuffer(file);
        }
      });
}
// Chuyển đổi Byte sang Hex
function convertByteToHex(data) {
  var hexChars = [];
  for (var i = 0; i < data.length; i++) {
    var hex = (data[i] & 0xff).toString(16);
    hexChars.push(hex.length === 1 ? "0" + hex : hex);
  }
  return hexChars.join("");
}

// Hàm Băm SHA-256
function getSHAHash(input) {
  try {
    var md = new TextEncoder().encode(input);
    return crypto.subtle.digest("SHA-256", md)
      .then(function (hash) {
        var hashArray = Array.from(new Uint8Array(hash));
        return convertByteToHex(hashArray);
      })
      .catch(function (error) {
        throw new Error(error);
      });
  } catch (error) {
    throw new Error(error);
  }
}
//Hàm chuyển Hash thành BigInt và mod cho p --> bản rõ Integer
function HashtoInt(hashValue,p){
  var bigIntHash = BigInt("0x" + hashValue);
  var bigInt_p = BigInt(p) - BigInt(1);
  var bigInt_m = bigIntHash % bigInt_p;
  return parseInt(bigInt_m.toString());
}
// Hàm tính Nghịch đảo trên modul p
function modInverse(k, p) {
  var [gcd, x, y] = extendedEuclidean(k, p);
  return (x % p + p) % p;
}
function extendedEuclidean(a, b) {
  if (b === 0) {
    return [a, 1, 0];
  }
  var [gcd, x1, y1] = extendedEuclidean(b, a % b);
  var x = y1;
  var y = x1 - Math.floor(a / b) * y1;
  return [gcd, x, y];
}
//Hàm mã hóa
function encrypt(banro,p,alpha,k,a){
  //tính khóa S1
  var S1 = modPow(alpha,k,p);
  //tính k nghịch đảo trên modul p
  var k_inverse = modInverse(k,p-1);
  var S2 = ((((k_inverse%(p-1))*(banro-a*S1))%(p-1))+(p-1))%(p-1);

  return {S1,S2};
  
}
//Hàm kiểm tra xem văn bản có bị chỉnh sửa hay k
function Verification(S1,S2,alpha,banro,p,beta)
{
    var V1 = modPow(alpha,banro,p);
    var V2 = ((modPow(beta,S1,p))*(modPow(S1,S2,p)))%p;

    if(V1===V2){
      return true;
    }
    return false;
}

$(document).ready(function(){
    //----------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------
    //Sự kiện khi nhấn nút tạo khóa
    $('#Key_create_btn').click(function () { 
        p = generatePrimeNumber();
        $('#Key_p').text(p);
        
        alpha = findPrimitiveRoot(p);
        $('#Key_alpha').text(alpha);

        a = generatePrivateKey(p);
        $('#Key_a').text(a);
        
        beta = modPow(alpha,a,p);
        $('#Key_beta').text(beta);

        k = chooseK(p);
        $('#Key_k').text(k);
        
    });

    //----------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------
    //sự kiện khi người dùng input file

    //input bản rõ của phần mã hóa
    readFile('#encrypt_inputFile','#encrypt_readFile_textbox');
    //input bản rõ của phần giải mã
    readFile('#decrypt_inputFile','#decrypt_readFile_textbox');
    //input bản mã của phần giải mã
    readFile('#decrypt_Key_inputFile','#decrypt_Key_textbox');
    //----------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------
    //sự kiện khi bấm nút kí
    $('#encrypt_btn').click(function(){
      if(p === null){
        alert("Vui lòng tạo khóa trước khi thực hiện ký");
        return;
      }
      if($('#encrypt_readFile_textbox').val() === ""){
        alert("Vui lòng upload file hoặc nhập bản rõ!");
        return;
      }
      //Bắt đầu thực hiện ký
      let content = $('#encrypt_readFile_textbox').val();
      getSHAHash(content)
        .then(function (result) {
          console.log(result);
          encrypt_banro = HashtoInt(result,p);
          var banma = encrypt(encrypt_banro,p,alpha,k,a);

          encrypt_banma_gamma = banma.S1;
          encrypt_banma_delta = banma.S2;
          console.log(banma.S1 + " " + banma.S2);
          crypto_string = "("+encrypt_banma_gamma+","+encrypt_banma_delta+")";

            //băm chuỗi khóa sang hash
            getSHAHash(crypto_string)
            .then(function (result) {
              crypto_hash = result;
              console.log(crypto_hash);
              $('.encrypted').text(crypto_hash);
            })
            .catch(function (error) {
              console.log(error); // Xử lý lỗi nếu có
            });


          
        })
        .catch(function (error) {
          console.log(error); // Xử lý lỗi nếu có
        });
      
        

    });
    //----------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------
    //sự kiện khi bấm nút lưu
    $('#save').click(function(){
        

    });


    //----------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------
    // Sự kiện khi bấm nút chuyển
    $('#rechoose').click(function(){
      $('#decrypt_readFile_textbox').val($('#encrypt_readFile_textbox').val());
      $('#decrypt_Key_textbox').val($('.encrypted').text());
    });
    //----------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------
    //sự kiện khi bấm nút kiểm tra chữ ký
    $('#check').click(function(){
      if($('#decrypt_Key_textbox').val()==="" || $('#decrypt_readFile_textbox').val()==="" ){
        alert("Vui lòng nhập đầy đủ thông tin!");
        return;
      }
      if(crypto_hash !== $('#decrypt_Key_textbox').val()){
        $('.result').text("Văn bản đã bị chỉnh sửa");
        return;
      }

      //Chuyen ban ro ve int
      var content =  $('#decrypt_readFile_textbox').val();
      getSHAHash(content)
            .then(function (result) {
              var check_banro = HashtoInt(result,p);
              if(Verification(encrypt_banma_gamma,encrypt_banma_delta,alpha,check_banro,p,beta)){
                $('.result').text("Văn bản hợp lệ");
                return;
              }
              $('.result').text("Văn bản đã bị chỉnh sửa");
            })
            .catch(function (error) {
              console.log(error); // Xử lý lỗi nếu có
            });





    });



})

