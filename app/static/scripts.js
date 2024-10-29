// app/static/scripts.js

document.addEventListener("DOMContentLoaded", function() {
    // 卡片悬停效果：当鼠标悬停时放大卡片
    var gridItems = document.querySelectorAll('.grid-item');
    
    gridItems.forEach(function(item) {
        item.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.05)';
            this.style.backgroundColor = '#f0f0f0';
        });
        
        item.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1)';
            this.style.backgroundColor = '#f9f9f9';
        });
    });

    // 页面过渡效果：点击卡片时淡出当前页面
    var links = document.querySelectorAll('.grid-item a');
    
    links.forEach(function(link) {
        link.addEventListener('click', function(event) {
            event.preventDefault();
            var href = this.getAttribute('href');
            document.body.style.opacity = '0';
            setTimeout(function() {
                window.location.href = href;
            }, 300);  // 300ms 的淡出效果
        });
    });

    // 通知系统：显示消息提示
    var notification = document.querySelector('.notification');
    
    if (notification) {
        // 自动隐藏通知
        setTimeout(function() {
            notification.style.opacity = '0';
            setTimeout(function() {
                notification.remove();
            }, 600);  // 600ms 的淡出效果
        }, 4000);  // 4秒后自动隐藏
    }
});
