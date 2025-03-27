using API.FornitureStore.Data;
using API.FurnitoreStore.Share;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.FurnitoreStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductCategoriesController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        public ProductCategoriesController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<IEnumerable<ProductCategory>> GetCategories()
        {
            return await _context.ProductCategories.ToListAsync();
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetDetails(int id)
        {
            var prodCategory = await _context.ProductCategories.FirstOrDefaultAsync(pc => pc.Id == id);
            if (prodCategory == null) 
                return NotFound();
            return Ok(prodCategory);
        }

        [HttpPost]
        public async Task<IActionResult> Post(ProductCategory prodCategory)
        {
            if (prodCategory == null) 
                return BadRequest();

            await _context.ProductCategories.AddAsync(prodCategory);
            await _context.SaveChangesAsync();
            return CreatedAtAction("Post", prodCategory.Id, prodCategory);
        }

        [HttpPut]
        public async Task<IActionResult> Put (ProductCategory prodCategory)
        {
            _context.ProductCategories.Update(prodCategory);
            await _context.SaveChangesAsync();
            return NoContent();
        }

        [HttpDelete]
        public async Task<IActionResult> Delete(ProductCategory prodCategory)
        {
            if (prodCategory == null)
                return NotFound();
            _context.ProductCategories.Remove(prodCategory);
            await _context.SaveChangesAsync();
            return NoContent();
        }
    }
}
