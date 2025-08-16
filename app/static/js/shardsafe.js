document.addEventListener("DOMContentLoaded", function () {
  //  first password
  const togglePassword1 = document.getElementById("togglePassword");
  const passwordInput1 = document.getElementById("password");
  const icon1 = document.getElementById("toggleIcon");

  togglePassword1.addEventListener("click", function () {
    const isPassword = passwordInput1.type === "password";
    passwordInput1.type = isPassword ? "text" : "password";
    icon1.classList.toggle("bi-eye");
    icon1.classList.toggle("bi-eye-slash");
  });
  //second password
  const togglePassword2 = document.getElementById("togglePassword2");
  if (togglePassword2){
    const passwordInput2 = document.getElementById("password2");
    const icon2 = document.getElementById("toggleIcon2");

    togglePassword2.addEventListener("click", function () {
      const isPassword = passwordInput2.type === "password";
      passwordInput2.type = isPassword ? "text" : "password";
      icon2.classList.toggle("bi-eye");
      icon2.classList.toggle("bi-eye-slash");
  });
  }
  
});

