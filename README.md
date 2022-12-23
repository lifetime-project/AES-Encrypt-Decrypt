# AES-Encrypt-Decrypt
AES 암복호화 (Java 17에서 작성 함)

```java
    public static void main(String[] args) {
        //secretKey, salt 생성 용 
        //RandomStringUtils를 사용하기 위해서는 org.apache.commons:commons-lang3:3.12.0 사용
//        String rand;
//        rand =  RandomStringUtils.randomAscii(64);
//        System.out.println("secretKey : " + rand);
//        rand =  RandomStringUtils.randomAscii(64);
//        System.out.println("salt : " + rand);


        //테스트
        String password = "PU#w%#rq#!%+$/y)c4FlI/)uH{/QqlK#*+(iNC<(t>Y^e6u!jH>,ki}y0lhBrWia";
        String text = "가나다라마바사";

        String encrypt = encrypt(text, password);
        System.out.println(encrypt);

        String decrypt = decrypt(encrypt, password);
        System.out.println(decrypt);

        System.out.println(text.equals(decrypt));
    }
```

결과
```text
fLFRzh0yoUOaHZxtxk1Oy3vomqCBT9nTAyD30r8xSbQ=
가나다라마바사
true
```