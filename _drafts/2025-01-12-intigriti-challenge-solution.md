---
title: "Intigriti January Challenge 0125"
date: 2024-01-12 11:47:00 +0530
author: piyush
categories: [XSS, CTF]
tags: [ctf, xss, initigriti]
---

Indeed this was an amazing challenge by [@0xGodson_](https://x.com/0xGodson_) hosted by [@Intigriti](https://x.com/intigriti), shoutout to them for hosting such intresting XSS challenges every month for us.

It took me almost 5 hrs to solve the challenge
![img-description](/assets/img/posts/intichall/report1.png){: w="500"}
## Here's all the code that was realted to the challenge
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
At first glance, this seemed like a simple challenge to me, as there was a basic XSS function checking if the hash fragment or the query parameters contained `<` or `>`, and if they did, the execution would stop.

```js
function XSS() {
    return decodeURIComponent(window.location.search).includes('<') ||
    decodeURIComponent(window.location.search).includes('>') ||
    decodeURIComponent(window.location.hash).includes('<') ||
    decodeURIComponent(window.location.hash).includes('>')
}
```
The input was being reflected in a `h2` tag, and we had to close that tag to inject our malicious payload after it. I tried spraying various payloads but didn't have any success. One interesting thing that kept bugging me was the regex used in these two lines:

```js
function getParameterByName(name) {
  var url = window.location.href;
  name = name.replace(/[\[\]]/g, '\\$&');
  var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)');



function checkQueryParam() {
  const text = getParameterByName('text');
```

Looking at the third line, it seemed like the `[` and `]` characters were just being escaped with a backslash, but the name parameter was constant (at line 9), and there seemed to be no way to modify it. I spent a lot of time thinking there might be a way to mutate the name parameter's value, but there was no way to do that. Out of frustration, I asked the challenge author about the line, and he confirmed it was of no use and was only there because the challenge was a replica of a real bug he found, where the original code had that behavior.

The fourth line looked suspicious to me, but I wasn't sure how to exploit it. The regex was used to capture the text parameter's value using capture groups. To simplify the regex, let me decode it for you:

- `[?&]`: Matches either `?` or `&` (to match the first query parameter `?text=`, or if not present, the second one with `&text=`)
- `name`: Literal value `text`
- `(=([^&#]*)|&|#|$)`: Matches either `=`, `&`, `#`, or the end of the string. The `=` part uses the capture group `([^&#]*)`, which matches any character any number of times, except for `&` and `#`.

I was stuck here for a long time. I tried inserting query parameters in hash fragments, but that was also captured by the XSS function.
`/challange#?text=payload`{: .filepath} 

I decided to move on with the regex, thinking it might be part of the original code.

## Another distraction
I noticed that while returning the value of the `text` query parameter, the function `getParameterByName` replaces certain characters in the string.
```js
return decodeURIComponent(results[2].replace(/\+/g, ' '));
```
It was replacing `+` (which represents a space in URL encoding) with a literal space. I thought this might be key—it seemed like interesting behavior, because the XSS function wasn't performing the same `replace` function. I thought if I encoded the `<` in URL encoding and inserted a `+` between the `%` and the hex value, the XSS function would decode only the `+` into a space and leave the rest of the part as-is. The idea was that the XSS function wouldn’t flag the `<` or `>` characters since they wouldn't be decoded. Meanwhile, getParameterByName would replace the `+` with a space, then decode the rest.

However, Lord JavaScript had other plans for me. JS throws an error when it doesn't find a valid hex value after `%`. After reading more about the `decodeURIComponent` function, I stumbled upon an MDN doc that mentioned the same code.
```js
results[2].replace(/\+/g, ' ');
```
It stated that this behavior was intended to replace the `+` with a space before decoding while working with query parameters, and that caused me some pain 🥲.

By this point, two hints had been released:
```text
Focus on the pattern, it's your guiding star, The way to the answer isn’t too far.

Did I say "the way"? Sorry, I meant "the path
```

Now I was sure that the solution required some kind of path quirk, and I had to focus on the evil regex. Simultaneously, I contacted Godson (the author), and he also pointed me in the same direction.

After a lot of random attempts, I saw something interesting:
When I added & after the URL, the server interpreted it as a valid path. I tried inserting `<>` with some payload, and it was a valid path and a `404 Not found`. Then I added `../` after the URL, and I was redirected to the `/challenge`{: .filepath} path. The browser normalized the path, but I wanted the server to normalize it, so I URL-encoded it as `..%2f` and this didn't redirected me to challenge path but served the challange page at the same time.
```text
/challenge/&kk/..%2f/
```
I was sure this would lead me to the solution. I modified the URL to `/challenge/&text=<test>/..%2f/`{: .filepath} and saw that everything after `/text=`{: .filepath`} was reflected into the `<h2>` tag. To confirm, when I ran the XSS function in the console, it returned false because the query parameters and hash fragments were both empty. I quickly inserted the following payload, and it triggered the sacred ✨ alert box.
```text
/challenge/&text=%3C%252fh2%3E%3Cimg%20src=x%20onerror=alert(1)%20%252f%3E/..%2f/
```

I encoded the `/` twice to avoid issues while the browser decoded the URL.

## Conclusion

That was the entire journey. I absolutely learned a lot while solving this challenge, and it was a wholesome experience filled with a number of emotions throughout.



