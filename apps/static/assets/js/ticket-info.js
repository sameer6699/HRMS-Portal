  const toggleBtn = document.getElementById('toggleViews');
  const viewsList = document.getElementById('viewsList');
  const toggleIcon = document.getElementById('toggleIcon');

  toggleBtn.addEventListener('click', function (event) {
    event.stopPropagation(); // Prevent dropdown from closing
    
    if (viewsList.style.display === "none" || viewsList.style.display === "") {
      viewsList.style.display = "block";
      toggleIcon.classList.remove('bi-chevron-down');
      toggleIcon.classList.add('bi-chevron-up');
    } else {
      viewsList.style.display = "none";
      toggleIcon.classList.remove('bi-chevron-up');
      toggleIcon.classList.add('bi-chevron-down');
    }
  });

  function setStatus(status) {
    const statusText = document.getElementById('statusText');
    const dropdownIcon = document.getElementById('dropdownIcon');
    
    if (status === 'Open') {
        statusText.style.color = 'red';
    } else if (status === 'On Hold') {
        statusText.style.color = 'orange';
    } else if (status === 'Escalated') {
        statusText.style.color = 'blue';
    } else if (status === 'Closed') {
        statusText.style.color = 'green';
    }

    statusText.innerText = status;
    toggleDropdownIcon(); 
}

function toggleDropdownIcon() {
    const dropdownIcon = document.getElementById('dropdownIcon');
    
    if (dropdownIcon.classList.contains('bi-chevron-down')) {
        dropdownIcon.classList.remove('bi-chevron-down');
        dropdownIcon.classList.add('bi-chevron-up');
    } else {
        dropdownIcon.classList.remove('bi-chevron-up');
        dropdownIcon.classList.add('bi-chevron-down');
    }
}
