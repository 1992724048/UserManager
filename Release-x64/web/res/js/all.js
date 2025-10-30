function playClickSound() {
  const audio = document.getElementById("click-sound");
  audio.play();
}

$(document).click(function () {
  playClickSound();
});
