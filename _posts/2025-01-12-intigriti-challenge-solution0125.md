---
title: "Intigriti January Challenge 0125"
date: 2024-01-12 11:47:00 +0530
author: piyush
categories: [CTF, XSS]
tags: [ctf, xss, initigriti]
---

This was truly an incredible [challenge](https://challenge-0125.intigriti.io/challenge) organized by [@0xGodson_](https://x.com/0xGodson_) and hosted by [@Intigriti](https://x.com/intigriti). A big shoutout to them for putting together such interesting XSS challenges for us every month. 

It took me nearly 5 hours to crack the challenge.
{:refdef: style="text-align: center;"}
![img-description](/assets/img/posts/intichall/report2.png){: w="300" refdef}
## Here’s the code related to the challenge.
```js
function XSS() {
  return decodeURIComponent(window.location.search).includes('<') ||
  decodeURIComponent(window.location.search).includes('>') ||
  decodeURIComponent(window.location.hash).includes('<') ||
  decodeURIComponent(window.location.hash).includes('>')
}

function getParameterByName(name) {
  var url = window.location.href;
  name = name.replace(/[\[\]]/g, '\\$&');
  var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)');
  results = regex.exec(url);
  if (!results) return null;
  if (!results[2]) return '';
  return decodeURIComponent(results[2].replace(/\+/g, ' '));
}

// Function to redirect on form submit
function redirectToText(event) {
  event.preventDefault();
  const inputBox = document.getElementById('inputBox');
  const text = encodeURIComponent(inputBox.value);
  window.location.href = `/challenge?text=${ text }`;
}

// Function to display modal if 'text' query param exists
function checkQueryParam() {
  const text = getParameterByName('text');
  if (text && XSS() === false) {
    const modal = document.getElementById('modal');
    const modalText = document.getElementById('modalText');
    modalText.innerHTML = `Welcome, ${ text }!`;
    textForm.remove()
    modal.style.display = 'flex';
  }
}
window.onload = function () {
  generateFallingParticles();
  checkQueryParam();
};
```

## Having the first look
At first glance, this appeared to be a straightforward challenge. There was a basic XSS function that checked whether the hash fragment or the query parameters included `<` or `>`. If either was found, the execution would halt.

```js
function XSS() {
    return decodeURIComponent(window.location.search).includes('<') ||
    decodeURIComponent(window.location.search).includes('>') ||
    decodeURIComponent(window.location.hash).includes('<') ||
    decodeURIComponent(window.location.hash).includes('>')
}
```
The input was displayed in an `h2` tag, and we needed to close that tag to insert our malicious payload afterward. I attempted to use different payloads but didn’t achieve any success. One intriguing aspect that continued to puzzle me was the regex utilized in these lines:

```js
function getParameterByName(name) {
  var url = window.location.href;
  name = name.replace(/[\[\]]/g, '\\$&');
  var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)');


function checkQueryParam() {
  const text = getParameterByName('text');
```

In the third line, it looked like the `[` and `]` characters were simply being escaped with a backslash. However, the name parameter remained constant (as seen in line 8), and there didn't seem to be any way to change it. I spent quite a bit of time wondering if there was a method to alter the value of the name parameter, but ultimately, I found there was no option for that. Frustrated, I reached out to the challenge author about that line, and he confirmed it was irrelevant and included only because the challenge was modeled after a real bug he encountered, where the original code exhibited that same behavior.

The fourth line sus to me, but I wasn't quite sure how to exploit it. The regex was utilized to extract the value of the text parameter through capture groups. To make the regex clearer, let me break it down for you:

- `[?&]`: Matches either `?` or `&` (to match the first query parameter `?text=`, or if not present, the second one with `&text=`)
- `name`: Literal value `text`
- `(=([^&#]*)|&|#|$)`: Matches either `=`, `&`, `#`, or the end of the string. The `=` part uses the capture group `([^&#]*)`, which matches any character any number of times, except for `&` and `#`.

I was stuck here for quite a while. I attempted to insert query parameters into hash fragments, but that too was intercepted by the XSS function.
`/challange#?text=payload`{: .filepath} 

I decided to step away from the regex, thinking it was probably a component of the original code as well.

## Another distraction
I observed that when retrieving the value of the `text` query parameter, the function `getParameterByName` alters specific characters in the string.
```js
return decodeURIComponent(results[2].replace(/\+/g, ' '));
```
It was replacing `+` (which represents a space in URL encoding) with an literal space. I thought this might be significant—it seemed like an interesting behavior, because the XSS function wasn't executing the same `replace` function. I figured that if I encoded the `<` using URL encoding and placed a `+` between the `%` and the hex value, the XSS function would only decode the `+` into a space and leave the rest unchanged. The idea was that the XSS function wouldn’t flag the `<` or `>` characters since they wouldn't be decoded. Meanwhile, `getParameterByName` would convert the `+` into a space, then decode the rest.

However, Lord JavaScript had different plans for me. JS throws an error if it can't find a valid hex value immediately after `%`. While researching the `decodeURIComponent` function, I came across an MDN document that discussed the same code.
```js
results[2].replace(/\+/g, ' ');
```
It mentioned that this behavior was intentional and was meant to replace the `+` with a space before decoding when dealing with query parameters, which caused me some pain 🥲.

At this point, two hints had already been shared:
```text
Focus on the pattern, it's your guiding star, The way to the answer isn’t too far.

Did I say "the way"? Sorry, I meant "the path
```

I was convinced that the solution was something around the URL path, so I turned my attention to the tricky regex. At the same time, I reached out to Godson, the author, and he confirmed that I was on the right track.

After numerous random attempts, I stumbled upon something intriguing: When I added an `&` after the URL, the server recognized it as a valid path. I experimented by inserting `<>` with some payload, which resulted in a valid path but returned a `404 Not Found`. Then, I appended `../` to the URL, and I was redirected to the `/challenge`{: .filepath} path. The browser normalized the path, but I wanted only the server to do the same, so I URL-encoded it as `..%2F`. This didn't redirect me to the challenge path, but it did serve the challenge page simultaneously.
```text
/challenge/&kk/..%2f/
```
I was confident this would bring me closer to the solution. I changed the URL to `/challenge/&text=<test>/..%2F/` and noticed that everything after `/text=` was displayed in the `<h2>` tag. To verify, when I executed the `XSS` function in the console, it returned `false` since both the query parameters and hash fragments were empty. I quickly added the following payload, and it popped the sacred ✨ alert box.
```text
https://challenge-0125.intigriti.io/challenge/&text=%3C%252fh2%3E%3Cimg%20src=x%20onerror=alert(document.domain)%20%252f%3E/..%2f/
```

I encoded the `/` twice to avoid issues while the browser decoded the URL.

## Conclusion

That was the entire journey. I absolutely learned a lot while solving this challenge, and it was a wholesome experience filled with a range of emotions along the way.



