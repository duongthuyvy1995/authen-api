using EntityFramework.Data;
using EntityFramework.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EntityFramework.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class ProductsController : ControllerBase
    {
        private readonly ApplicationDBContext _applicationDBContext;


        public ProductsController(ApplicationDBContext applicationDBContext)
        {
            _applicationDBContext = applicationDBContext;
        }

        [Authorize(Roles = "Admin, Member")]
        public IActionResult GetProducts()
        {

            var products = _applicationDBContext.Products.Include(x => x.Category)
                .Select(x => new ProductViewModel
                {
                    Id = x.Id,
                    Name = x.Name,
                    Price = x.Price,
                    CategoryName = x.Category.Name
                }).ToList();

            return Ok(products);
        }
        
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult AddProduct([FromBody] ProductViewModel product)
        {
            var item = new Product()
            {
                CategoryId = 1,
                Name = product.Name,
                Price = product.Price
            };
            _applicationDBContext.Add(item);
            _applicationDBContext.SaveChanges();

            return Ok();
        }
    }
}
