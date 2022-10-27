String.prototype.toDOM=function(){
    var d=document
        ,i
        ,a=d.createElement("div")
        ,b=d.createDocumentFragment();
    a.innerHTML=this;
    while(i=a.firstChild)b.appendChild(i);
    return b;
};

const refresh = body => {
    let tenants = [];
    for (let tenant of body.tokens) {

        const template = document.getElementById("tenant");
        template.content.querySelector(".tenant_name").textContent = tenant.tenant;
        template.content.querySelector(".tenant_description").textContent = tenant.description;
        template.content.querySelector(".tenant_copy").setAttribute("data-biscuit", tenant.token);
        template.content.querySelector(".tenant_copy").setAttribute("onclick", " copy(this)")
        template.content.querySelector(".tenant_delete").setAttribute("data-tenant", tenant.tenant);
        template.content.querySelector(".tenant_delete").setAttribute("onclick", " delete_tenant(this)")
        tenants.push(template.content.cloneNode(true))
    }


    let tenants_table = document.querySelector("#tenants");
    tenants_table.replaceChildren(...tenants)
}

const copy = async (e) => {
    let biscuit = e.getAttribute("data-biscuit");
    e.textContent = "Copied!";
    let that = e;
    setTimeout(() => {
        that.textContent = "Copy"
    }, 2000)
    navigator.clipboard.writeText(biscuit)
}

document.addEventListener("DOMContentLoaded", async () => {
    let response = await fetch("/api/list", {
        method: "get",
        mode: "same-origin",
        headers: {
            'Content-Type': 'application/json'
        }
    });

    if (response.status === 200) {

        const body = await response.json();
        console.log(body)

        refresh(body)

    }
})

const delete_tenant = async (e) => {
    let tenant = e.getAttribute("data-tenant");

    const data = {
        tenant
    };
    let response = await fetch("/api/delete", {
        method: "delete",
        body: JSON.stringify(data),
        mode: "same-origin",
        headers: {
            'Content-Type': 'application/json'
        }
    });

    if (response.status === 200) {

        const body = await response.json();

        refresh(body)

    }
}

const create_tenant = async (e) => {
    let description = e.parentNode.querySelector("#description").value;

    if (description.trim() === "") {
        return
    }

    e.parentNode.querySelector("#description").value = ""
    const data = {
        description
    };
    let response = await fetch("/api/create", {
        method: "post",
        body: JSON.stringify(data),
        mode: "same-origin",
        headers: {
            'Content-Type': 'application/json'
        }
    });

    if (response.status === 200) {

        const body = await response.json();

        refresh(body)

    }
}