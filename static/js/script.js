document.addEventListener("DOMContentLoaded", () => {
  const otp = document.querySelector(".otp");
  if (otp) otp.addEventListener("input", () => otp.value = otp.value.replace(/\D/g,"").slice(0,6));
  const btn = document.getElementById("resendBtn"), timer = document.getElementById("timer");
  if (btn && timer) {
    let left = 60; btn.disabled = true;
    const tick = () => { timer.textContent = ` (${left}s)`; if(left <= 0){btn.disabled=false; timer.textContent="";} else {left--; setTimeout(tick,1000);} };
    tick();
  }
});
