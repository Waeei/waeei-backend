
document.addEventListener("DOMContentLoaded", function () {

  if (!document.getElementById("simpleModeBtn")) {
    const btn = document.createElement("button");
    btn.id = "simpleModeBtn";
    btn.textContent = "الوضع البسيط";
    Object.assign(btn.style, {
      position: "fixed",
      bottom: "20px",
      left: "20px",
      padding: "12px 20px",
      background: "#0E3637",
      color: "white",
      border: "none",
      borderRadius: "10px",
      fontSize: "16px",
      cursor: "pointer",
      zIndex: "9999",
    });
    document.body.appendChild(btn);
  }

  const btn = document.getElementById("simpleModeBtn");

  btn.addEventListener("click", function () {
    const path = window.location.pathname;

    let steps = [];

    if (path.includes("detection")) {
      steps = [
        { element: ".feature-box:nth-child(1)", intro: "هذا الزر يسمح لك بإدخال الرسالة المشبوهة للتحقق منها." },
        { element: ".feature-box:nth-child(2)", intro: "هنا ترفع لقطة شاشة للمحادثة ليتم فحصها." },
        { element: "#verifyBtn", intro: "اضغط هنا لبدء التحقق من الرسائل أو الصور." }
      ];
    }
    else if (path.includes("textbox")) {
      steps = [
        { element: "#textbox", intro: "أدخل الرابط المشبوه هنا." },
        { element: "#sendBtn", intro: "بعد إدخال الرابط، اضغط إرسال ليتم التحقق." }
      ];
    }

    else if (path.includes("graph")) {
      steps = [
        { element: "#main-image", intro: "هنا يتم عرض الإحصاءات الخاصة بمحاولات الاحتيال." },
        { element: ".navbar", intro: "من هنا يمكنك التنقل بين الصفحات." }
      ];
    }

    else {
      steps = [
        { intro: "مرحبًا! هذا هو الوضع البسيط في منصة واعي لمساعدتك في التنقل بسهولة." }
      ];
    }

    const intro = introJs();
    intro.setOptions({
      steps: steps,
      nextLabel: 'التالي',
      prevLabel: 'السابق',
      doneLabel: 'تم',
      showProgress: true,
      showBullets: false,
    });
    intro.start();
  });
});