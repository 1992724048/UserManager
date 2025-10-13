// 播放点击音效
function playClickSound() {
    const audio = document.getElementById('click-sound');
    audio.play();
}

// 为所有按钮和输入框添加点击事件
$(document).click(function () {
    playClickSound();
});