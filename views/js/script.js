async function getAuthors(params) {
    
    const accessToken = localStorage.getItem("accessToken")

    fetch("http://localhost:3003/api/author/login", {
        method: 'GET',
        headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json"
        },
        mode: "cors"
    })
        .then((res) => {
            if (res.ok) {
                return res.json()
            }
            else {
                console.log("Request failed with status: " + res.status);
            }
        })
        .then((authors) => {
            console.log(authors.data)
            displayAuthor(authors.data)
        })
        .catch((err) => {
            console.error("error:", err);
        })
}

function displayAuthor(authors) {
    const authorList = document.getElementById("author-list")
    authors.forEach(author => {
        const listItem = document.createElement('li')
        listItem.textContent = `${author_first_name} ${author_last_name} - ${author_email}`
        authorList.appendChild(listItem)
    });
}

